import {
  checkoutEtag,
  parseCheckout,
  parseCheckoutCreated,
  parsePaymentConfiguration,
  parseTransaction,
} from './checkout-api';

const money = { amountInCents: 1_000, currency: 'COP' as const };
const quote = {
  quoteId: 'quote_12345678',
  version: 1,
  productId: 'product_123456',
  quantity: 1 as const,
  subtotal: money,
  baseFee: money,
  deliveryFee: money,
  total: { amountInCents: 3_000, currency: 'COP' as const },
  expiresAt: '2099-01-01T00:00:00Z',
};
const product = {
  productId: 'product_123456',
  sku: 'SKU_1',
  name: 'Producto',
  description: 'Producto sintético',
  imageUrl: 'http://localhost/product.svg',
  unitPrice: money,
  available: 1,
};

describe('checkout API runtime contracts', () => {
  it('parses created and recovered checkouts and rejects drift', () => {
    const created = {
      checkoutId: 'checkout_123456',
      status: 'DRAFT',
      version: 1,
      quote,
      expiresAt: '2099-01-01T00:30:00Z',
    };
    expect(parseCheckoutCreated(created)).toEqual(created);
    expect(
      parseCheckout({
        ...created,
        product,
        customer: null,
        deliveryDetails: null,
        activeTransactionId: null,
      }),
    ).toMatchObject({ product, status: 'DRAFT' });
    expect(() => parseCheckoutCreated({ ...created, total: money })).toThrow();
    expect(() => parseCheckout({ ...created, product: { ...product, available: -1 } })).toThrow();
    expect(() => parseCheckoutCreated({ ...created, expiresAt: 'tomorrow' })).toThrow();
    expect(() =>
      parseCheckout({
        ...created,
        product: {
          ...product,
          unitPrice: { amountInCents: 1_000_000_000_000, currency: 'COP' },
        },
      }),
    ).toThrow();
  });

  it('requires both independent acceptance contracts', () => {
    const configuration = {
      captureVariant: 'FAKE_CONTRACT',
      sandboxPublicKey: 'public-synthetic',
      allowedInstallments: [1, 3],
      acceptanceContracts: [
        {
          type: 'TERMS',
          permalink: 'https://example.test/terms',
          version: 'v1',
          acceptanceToken: 'terms-synthetic',
        },
        {
          type: 'PERSONAL_DATA',
          permalink: 'https://example.test/privacy',
          version: 'v1',
          acceptanceToken: 'privacy-synthetic',
        },
      ],
      expiresAt: '2099-01-01T00:00:00Z',
    };
    expect(parsePaymentConfiguration(configuration)).toEqual(configuration);
    expect(() =>
      parsePaymentConfiguration({ ...configuration, allowedInstallments: [1, 1] }),
    ).toThrow();
    expect(() =>
      parsePaymentConfiguration({
        ...configuration,
        acceptanceContracts: [
          configuration.acceptanceContracts[0],
          configuration.acceptanceContracts[0],
        ],
      }),
    ).toThrow('Both acceptance contracts are required');
  });

  it('parses canonical transaction states and strong ETags', () => {
    const transaction = {
      transactionId: 'transaction_123456',
      checkoutId: 'checkout_123456',
      checkoutStatus: 'PAYMENT_PENDING',
      paymentStatus: 'PENDING',
      dispatchPhase: 'UNKNOWN',
      providerStatus: null,
      reservationStatus: 'ACTIVE',
      integrityStatus: 'OK',
      recoveryCode: 'PROVIDER_OUTCOME_UNKNOWN',
      statusUrl: '/api/v1/transactions/transaction_123456',
      allowedActions: ['QUERY', 'WAIT', 'RETURN_TO_PRODUCT'],
      retryAfterSeconds: 3,
      acceptedAt: '2026-01-01T00:00:00Z',
      updatedAt: '2026-01-01T00:00:01Z',
    };
    expect(parseTransaction(transaction)).toEqual(transaction);
    expect(checkoutEtag(7)).toBe('"checkout-v7"');
    expect(() => parseTransaction({ ...transaction, paymentStatus: 'UNKNOWN' })).toThrow();
    expect(() =>
      parseTransaction({ ...transaction, allowedActions: ['QUERY', 'QUERY'] }),
    ).toThrow();
    expect(() => parseTransaction({ ...transaction, updatedAt: 'not-a-date' })).toThrow();
  });
});
