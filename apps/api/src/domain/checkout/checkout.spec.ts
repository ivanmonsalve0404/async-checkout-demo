import type { Transaction } from './checkout';
import {
  allowedActionsFor,
  checkoutStatusForPayment,
  etagFor,
  isTerminalPayment,
} from './checkout';

const transaction = (overrides: Partial<Transaction> = {}): Transaction => ({
  transactionId: 'transaction-001',
  checkoutId: 'checkout-001',
  providerReference: 'reference-001',
  paymentStatus: 'PENDING',
  dispatchPhase: 'ACKNOWLEDGED',
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
  updatedAt: '2026-01-01T00:00:00.000Z',
  amountInCents: 3_200_000,
  attempts: 0,
  currency: 'COP',
  effectsApplied: false,
  ...overrides,
});

describe('checkout domain policies', () => {
  it('formats strong checkout versions', () => {
    expect(etagFor(7)).toBe('"checkout-v7"');
  });

  it.each([
    ['PENDING', false],
    ['APPROVED', true],
    ['DECLINED', true],
    ['VOIDED', true],
    ['ERROR', true],
  ] as const)('classifies terminal state %s', (status, expected) => {
    expect(isTerminalPayment(status)).toBe(expected);
  });

  it.each([
    ['PENDING', 'PAYMENT_PENDING'],
    ['APPROVED', 'PAID'],
    ['DECLINED', 'PAYMENT_FAILED'],
    ['VOIDED', 'PAYMENT_FAILED'],
    ['ERROR', 'PAYMENT_FAILED'],
  ] as const)('maps payment %s to checkout %s', (payment, checkout) => {
    expect(checkoutStatusForPayment(payment)).toBe(checkout);
  });

  it('exposes conservative actions for pending, conflicted and safe final payments', () => {
    expect(allowedActionsFor(transaction())).toEqual(['QUERY', 'WAIT', 'RETURN_TO_PRODUCT']);
    expect(
      allowedActionsFor(
        transaction({ paymentStatus: 'APPROVED', integrityStatus: 'APPROVED_INVENTORY_CONFLICT' }),
      ),
    ).toEqual(['QUERY', 'RETURN_TO_PRODUCT', 'CONTACT_SUPPORT']);
    expect(allowedActionsFor(transaction({ paymentStatus: 'APPROVED' }))).toEqual([
      'QUERY',
      'RETURN_TO_PRODUCT',
    ]);
    expect(allowedActionsFor(transaction({ paymentStatus: 'DECLINED' }))).toEqual([
      'QUERY',
      'RETURN_TO_PRODUCT',
      'CONTACT_SUPPORT',
    ]);
    for (const paymentStatus of ['DECLINED', 'ERROR', 'VOIDED'] as const) {
      expect(
        allowedActionsFor(
          transaction({
            paymentStatus,
            reservationStatus: 'RELEASED',
            effectsApplied: true,
          }),
        ),
      ).toEqual(['QUERY', 'RETURN_TO_PRODUCT', 'START_NEW_CHECKOUT']);
    }
  });
});
