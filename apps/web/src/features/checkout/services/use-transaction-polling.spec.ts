import { act, renderHook } from '@testing-library/react';
import type { TransactionResponse } from '../api/checkout-api';
import { transactionPollingDelaysMs, useTransactionPolling } from './use-transaction-polling';

const acceptedAt = '2026-01-01T00:00:00.000Z';
const transaction: TransactionResponse = {
  transactionId: 'transaction_123456',
  checkoutId: 'checkout_123456',
  checkoutStatus: 'PAYMENT_PENDING',
  paymentStatus: 'PENDING',
  dispatchPhase: 'ACKNOWLEDGED',
  providerStatus: 'PENDING',
  reservationStatus: 'ACTIVE',
  integrityStatus: 'OK',
  statusUrl: '/api/v1/transactions/transaction_123456',
  allowedActions: ['QUERY', 'WAIT', 'RETURN_TO_PRODUCT'],
  acceptedAt,
  updatedAt: acceptedAt,
};

describe('transaction polling policy', () => {
  beforeEach(() => {
    jest.useFakeTimers();
    jest.setSystemTime(new Date(acceptedAt));
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('polls deterministically at 2, 3, 5, 8, then 10 seconds', async () => {
    const refetch = jest.fn().mockResolvedValue(undefined);
    renderHook(() => useTransactionPolling(transaction.transactionId, transaction, refetch));

    for (const [index, delay] of [...transactionPollingDelaysMs, 10_000].entries()) {
      await act(async () => jest.advanceTimersByTimeAsync(delay - 1));
      expect(refetch).toHaveBeenCalledTimes(index);
      await act(async () => jest.advanceTimersByTimeAsync(1));
      expect(refetch).toHaveBeenCalledTimes(index + 1);
    }
  });

  it('stops at ten minutes and leaves manual recovery available', async () => {
    jest.setSystemTime(new Date(Date.parse(acceptedAt) + 10 * 60 * 1_000 - 1));
    const refetch = jest.fn().mockResolvedValue(undefined);
    const { result } = renderHook(() =>
      useTransactionPolling(transaction.transactionId, transaction, refetch),
    );

    await act(async () => jest.advanceTimersByTimeAsync(1));

    expect(result.current.automaticPollingStopped).toBe(true);
    expect(refetch).not.toHaveBeenCalled();
  });

  it('cancels the pending timer on unmount', async () => {
    const refetch = jest.fn().mockResolvedValue(undefined);
    const { unmount } = renderHook(() =>
      useTransactionPolling(transaction.transactionId, transaction, refetch),
    );

    unmount();
    await act(async () => jest.advanceTimersByTimeAsync(2_000));

    expect(refetch).not.toHaveBeenCalled();
  });
});
