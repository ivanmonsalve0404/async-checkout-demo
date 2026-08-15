import {
  attemptRestarted,
  checkoutCreated,
  checkoutRecovered,
  checkoutReducer,
  closeCheckout,
  createIdempotencyKey,
  initialCheckoutState,
  openCheckout,
  progressCleared,
  returnedToProduct,
  returnNoticeCleared,
  stepChanged,
  transactionAccepted,
} from './checkout-slice';

describe('checkout UI state', () => {
  it('tracks the allowlisted journey and clears it terminally', () => {
    let state = checkoutReducer(initialCheckoutState, openCheckout());
    expect(state.modalOpen).toBe(true);
    state = checkoutReducer(
      state,
      checkoutCreated({
        checkoutId: 'checkout_123456',
        idempotencyKey: 'idem_1234567890123456',
      }),
    );
    state = checkoutReducer(state, stepChanged('review'));
    state = checkoutReducer(state, transactionAccepted('transaction_123456'));
    expect(state).toMatchObject({ step: 'status', transactionId: 'transaction_123456' });
    state = checkoutReducer(state, closeCheckout());
    expect(state.modalOpen).toBe(false);
    state = checkoutReducer(state, progressCleared());
    expect(state.checkoutId).toBeUndefined();
  });

  it('recovers, rotates a failed attempt, and returns without stale IDs', () => {
    let state = checkoutReducer(
      initialCheckoutState,
      checkoutRecovered({
        checkoutId: 'checkout_123456',
        transactionId: 'transaction_123456',
      }),
    );
    expect(state.step).toBe('status');
    state = checkoutReducer(state, attemptRestarted('idem_abcdefghijklmnop'));
    expect(state).toMatchObject({ step: 'payment', idempotencyKey: 'idem_abcdefghijklmnop' });
    expect(state.transactionId).toBeUndefined();
    state = checkoutReducer(state, returnedToProduct('FAILED'));
    expect(state.returnNotice).toBe('FAILED');
    state = checkoutReducer(state, returnNoticeCleared());
    expect(state.returnNotice).toBeUndefined();
  });

  it('creates an opaque idempotency key with sufficient entropy', () => {
    expect(createIdempotencyKey()).toMatch(/^idem_[a-f0-9]{36}$/);
  });
});
