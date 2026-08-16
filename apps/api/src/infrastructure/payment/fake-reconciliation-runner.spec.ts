import type { AppConfig } from '../configuration/app-config';
import type { CheckoutService } from '../../application/use-cases/checkout-service';
import { FakeReconciliationRunner } from './fake-reconciliation-runner';
import type { SafeLogger } from '../logging/safe-logger';

const config = (paymentAdapter: 'fake' | 'sandbox'): AppConfig =>
  ({ paymentAdapter, fakeReconcileIntervalMs: 50 }) as AppConfig;

const tick = (runner: FakeReconciliationRunner): Promise<void> =>
  (runner as unknown as { tick(): Promise<void> }).tick();

const logger = (): SafeLogger => ({ info: jest.fn() }) as unknown as SafeLogger;

describe('FakeReconciliationRunner', () => {
  afterEach(() => {
    jest.useRealTimers();
  });

  it('starts and stops a non-blocking interval only for the fake adapter', async () => {
    jest.useFakeTimers();
    const service = { reconcileDue: jest.fn().mockResolvedValue({ ok: true, value: [] }) };
    const fake = new FakeReconciliationRunner(
      service as unknown as CheckoutService,
      config('fake'),
      logger(),
    );
    const sandbox = new FakeReconciliationRunner(
      service as unknown as CheckoutService,
      config('sandbox'),
      logger(),
    );

    sandbox.onModuleInit();
    fake.onModuleInit();
    await jest.advanceTimersByTimeAsync(50);
    expect(service.reconcileDue).toHaveBeenCalledTimes(1);
    sandbox.onModuleDestroy();
    fake.onModuleDestroy();
    await jest.advanceTimersByTimeAsync(100);
    expect(service.reconcileDue).toHaveBeenCalledTimes(1);
  });

  it('contains a scheduled rejection and runs the following tick', async () => {
    jest.useFakeTimers();
    const service = {
      reconcileDue: jest
        .fn()
        .mockRejectedValueOnce(new Error('synthetic'))
        .mockResolvedValue({ ok: true, value: [] }),
    };
    const info = jest.fn();
    const safeLogger = { info } as unknown as SafeLogger;
    const runner = new FakeReconciliationRunner(
      service as unknown as CheckoutService,
      config('fake'),
      safeLogger,
    );
    runner.onModuleInit();
    await jest.advanceTimersByTimeAsync(50);
    await jest.advanceTimersByTimeAsync(50);
    expect(service.reconcileDue).toHaveBeenCalledTimes(2);
    expect(info).toHaveBeenCalledWith('payment.reconciliation.failed', {});
    runner.onModuleDestroy();
  });

  it('skips overlapping work and always releases its in-process guard', async () => {
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    const service = { reconcileDue: jest.fn().mockReturnValueOnce(blocked) };
    const runner = new FakeReconciliationRunner(
      service as unknown as CheckoutService,
      config('fake'),
      logger(),
    );

    const first = tick(runner);
    await tick(runner);
    expect(service.reconcileDue).toHaveBeenCalledTimes(1);
    release();
    await first;

    service.reconcileDue.mockRejectedValueOnce(new Error('synthetic'));
    await expect(tick(runner)).rejects.toThrow('synthetic');
    service.reconcileDue.mockResolvedValueOnce({ ok: true, value: [] });
    await expect(tick(runner)).resolves.toBeUndefined();
    expect(service.reconcileDue).toHaveBeenCalledTimes(3);
  });
});
