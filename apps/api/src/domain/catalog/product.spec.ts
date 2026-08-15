import { createProductSeed } from '../../infrastructure/persistence/product-seed';
import { isConsistentAvailability, parseProductId } from './product';

describe('product domain', () => {
  it('validates opaque product IDs', () => {
    expect(parseProductId('product-demo-001').ok).toBe(true);
    expect(parseProductId('bad/id').ok).toBe(false);
  });

  it('enforces inventory and money invariants', () => {
    const product = createProductSeed('product-demo-001', 'http://localhost:5173');
    expect(isConsistentAvailability(product)).toBe(true);
    expect(isConsistentAvailability({ ...product, reserved: -1 })).toBe(false);
    expect(
      isConsistentAvailability({ ...product, unitPrice: { amountInCents: 1.2, currency: 'COP' } }),
    ).toBe(false);
  });
});
