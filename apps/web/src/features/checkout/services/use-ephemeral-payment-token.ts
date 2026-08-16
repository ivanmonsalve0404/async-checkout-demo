import { useCallback, useEffect, useRef } from 'react';

export const paymentTokenTtlMs = 5 * 60 * 1_000;

export const useEphemeralPaymentToken = (
  onExpired: () => void,
): Readonly<{
  clear: () => void;
  get: () => string | undefined;
  set: (token: string) => void;
}> => {
  const valueRef = useRef<{ readonly token: string; readonly expiresAt: number } | undefined>(
    undefined,
  );
  const timerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  const clear = useCallback((): void => {
    valueRef.current = undefined;
    if (timerRef.current !== undefined) {
      globalThis.clearTimeout(timerRef.current);
      timerRef.current = undefined;
    }
  }, []);

  const set = useCallback(
    (token: string): void => {
      clear();
      valueRef.current = { token, expiresAt: Date.now() + paymentTokenTtlMs };
      timerRef.current = globalThis.setTimeout(() => {
        valueRef.current = undefined;
        timerRef.current = undefined;
        onExpired();
      }, paymentTokenTtlMs);
    },
    [clear, onExpired],
  );

  const get = useCallback((): string | undefined => {
    const current = valueRef.current;
    if (current === undefined) {
      return undefined;
    }
    if (Date.now() >= current.expiresAt) {
      clear();
      onExpired();
      return undefined;
    }
    return current.token;
  }, [clear, onExpired]);

  useEffect(() => clear, [clear]);

  return { clear, get, set };
};
