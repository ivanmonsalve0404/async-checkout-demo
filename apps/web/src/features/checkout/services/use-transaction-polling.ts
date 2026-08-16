import { useEffect, useState } from 'react';
import type { TransactionResponse } from '../api/checkout-api';

export const transactionPollingDelaysMs = [2_000, 3_000, 5_000, 8_000, 10_000] as const;
export const transactionPollingWindowMs = 10 * 60 * 1_000;

export const transactionPollingDelayMs = (attempt: number): number =>
  transactionPollingDelaysMs[Math.min(attempt, transactionPollingDelaysMs.length - 1)] ??
  transactionPollingDelaysMs.at(-1) ??
  10_000;

export const useTransactionPolling = (
  transactionId: string | undefined,
  transaction: TransactionResponse | undefined,
  refetch: () => Promise<unknown>,
): { readonly automaticPollingStopped: boolean } => {
  const [attempt, setAttempt] = useState(0);
  const [automaticPollingStopped, setAutomaticPollingStopped] = useState(false);

  useEffect(() => {
    setAttempt(0);
    setAutomaticPollingStopped(false);
  }, [transactionId]);

  useEffect(() => {
    if (transactionId === undefined || transaction?.paymentStatus !== 'PENDING') {
      setAutomaticPollingStopped(false);
      return;
    }

    const deadline = Date.parse(transaction.acceptedAt) + transactionPollingWindowMs;
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      setAutomaticPollingStopped(true);
      return;
    }

    setAutomaticPollingStopped(false);
    let active = true;
    const timer = globalThis.setTimeout(
      () => {
        if (Date.now() >= deadline) {
          if (active) setAutomaticPollingStopped(true);
          return;
        }
        void Promise.resolve()
          .then(refetch)
          .catch(() => undefined)
          .finally(() => {
            if (active) setAttempt((current) => current + 1);
          });
      },
      Math.min(transactionPollingDelayMs(attempt), remaining),
    );

    return () => {
      active = false;
      globalThis.clearTimeout(timer);
    };
  }, [attempt, refetch, transaction?.acceptedAt, transaction?.paymentStatus, transactionId]);

  return { automaticPollingStopped };
};
