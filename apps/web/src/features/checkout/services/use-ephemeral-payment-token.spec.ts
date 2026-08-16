import { act, renderHook } from '@testing-library/react';
import { paymentTokenTtlMs, useEphemeralPaymentToken } from './use-ephemeral-payment-token';

describe('ephemeral payment token', () => {
  beforeEach(() => {
    jest.useFakeTimers();
    jest.setSystemTime(new Date('2026-01-01T00:00:00Z'));
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('expires at five minutes and cannot return the stale token', () => {
    const onExpired = jest.fn();
    const { result } = renderHook(() => useEphemeralPaymentToken(onExpired));

    act(() => result.current.set('tok_fake_synthetic123'));
    act(() => jest.advanceTimersByTime(paymentTokenTtlMs - 1));
    expect(result.current.get()).toBe('tok_fake_synthetic123');

    act(() => jest.advanceTimersByTime(1));
    expect(result.current.get()).toBeUndefined();
    expect(onExpired).toHaveBeenCalledTimes(1);
  });

  it('fails closed against clock jumps and cancels cleanup on unmount', () => {
    const onExpired = jest.fn();
    const { result, unmount } = renderHook(() => useEphemeralPaymentToken(onExpired));

    act(() => result.current.set('tok_fake_synthetic123'));
    jest.setSystemTime(Date.now() + paymentTokenTtlMs);
    expect(result.current.get()).toBeUndefined();
    expect(onExpired).toHaveBeenCalledTimes(1);

    act(() => result.current.set('tok_fake_second123'));
    unmount();
    act(() => jest.advanceTimersByTime(paymentTokenTtlMs));
    expect(onExpired).toHaveBeenCalledTimes(1);
  });
});
