import type {
  CheckoutView,
  TransactionView,
} from '../../../application/use-cases/checkout-service';
import type {
  Checkout,
  Delivery,
  PaymentSubmission,
  Transaction,
} from '../../../domain/checkout/checkout';
import { createProductSeed } from '../../../infrastructure/persistence/product-seed';
import {
  presentCheckout,
  presentCheckoutCreated,
  presentCustomer,
  presentDelivery,
  presentDeliveryDetails,
  presentSubmission,
  presentTransaction,
} from './checkout.presenter';

const product = createProductSeed('product-demo-001', 'http://localhost:5173');
const checkout: Checkout = {
  checkoutId: 'checkout-001',
  status: 'DRAFT',
  version: 1,
  capabilityHash: 'capability-hash',
  productId: product.productId,
  quote: {
    quoteId: 'quote-001',
    version: 1,
    productId: product.productId,
    quantity: 1,
    subtotal: product.unitPrice,
    baseFee: { amountInCents: 200_000, currency: 'COP' },
    deliveryFee: { amountInCents: 500_000, currency: 'COP' },
    total: { amountInCents: 3_200_000, currency: 'COP' },
    expiresAt: '2026-01-01T00:05:00.000Z',
  },
  expiresAt: '2026-01-01T00:10:00.000Z',
};

const transaction = (overrides: Partial<Transaction> = {}): Transaction => ({
  transactionId: 'transaction-001',
  checkoutId: checkout.checkoutId,
  providerReference: 'reference-001',
  paymentStatus: 'PENDING',
  dispatchPhase: 'UNKNOWN',
  providerStatus: 'PENDING',
  reservationStatus: 'ACTIVE',
  integrityStatus: 'OK',
  acceptanceEvidence: {
    termsVersion: 'terms-v1',
    termsContractHash: 'terms-contract-hash-synthetic',
    personalDataVersion: 'personal-data-v1',
    personalDataContractHash: 'personal-data-contract-hash-synthetic',
    acceptedAt: '2026-01-01T00:00:00.000Z',
  },
  acceptedAt: '2026-01-01T00:00:00.000Z',
  updatedAt: '2026-01-01T00:00:01.000Z',
  amountInCents: 3_200_000,
  attempts: 0,
  currency: 'COP',
  effectsApplied: false,
  ...overrides,
});

describe('checkout presenters', () => {
  it('never exposes capability hashes in created or fetched checkout views', () => {
    expect(presentCheckoutCreated(checkout)).toEqual({
      checkoutId: checkout.checkoutId,
      status: 'DRAFT',
      version: 1,
      quote: checkout.quote,
      expiresAt: checkout.expiresAt,
    });
    const presented = presentCheckout({ checkout, product } satisfies CheckoutView);
    expect(presented).toMatchObject({
      customer: null,
      deliveryDetails: null,
      activeTransactionId: null,
    });
    expect(presented).not.toHaveProperty('capabilityHash');
  });

  it('presents customer/delivery drafts and submissions without transformations', () => {
    expect(presentCustomer(checkout)).toBeUndefined();
    expect(presentDeliveryDetails(checkout)).toBeUndefined();
    const submission: PaymentSubmission = {
      transactionId: 'transaction-001',
      statusUrl: '/api/v1/transactions/transaction-001',
      submissionState: 'ACCEPTED',
      acceptedAt: '2026-01-01T00:00:00.000Z',
    };
    expect(presentSubmission(submission)).toBe(submission);
  });

  it('adds retry guidance only while pending and optional recovery/final delivery only when present', () => {
    const pending = presentTransaction({
      transaction: transaction(),
      checkout,
      allowedActions: ['QUERY', 'WAIT'],
    } satisfies TransactionView);
    expect(pending).toMatchObject({ retryAfterSeconds: 1, providerStatus: 'PENDING' });
    expect(pending).not.toHaveProperty('deliveryId');
    expect(pending).not.toHaveProperty('recoveryCode');

    const final = presentTransaction({
      transaction: transaction({
        paymentStatus: 'APPROVED',
        providerStatus: 'APPROVED',
        reservationStatus: 'CONSUMED',
        deliveryId: 'delivery-001',
        recoveryCode: 'STATE_TRANSITION_CONFLICT',
      }),
      checkout: { ...checkout, status: 'PAID' },
      allowedActions: ['QUERY', 'CONTACT_SUPPORT'],
    } satisfies TransactionView);
    expect(final).toMatchObject({
      deliveryId: 'delivery-001',
      recoveryCode: 'STATE_TRANSITION_CONFLICT',
    });
    expect(final).not.toHaveProperty('retryAfterSeconds');
  });

  it('returns delivery resources unchanged', () => {
    const delivery: Delivery = {
      deliveryId: 'delivery-001',
      checkoutId: checkout.checkoutId,
      transactionId: 'transaction-001',
      status: 'CREATED',
      destination: { addressLine1: 'Calle 1', city: 'Bogota', region: 'Cundinamarca' },
      createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-01-01T00:00:00.000Z',
    };
    expect(presentDelivery(delivery)).toBe(delivery);
  });
});
