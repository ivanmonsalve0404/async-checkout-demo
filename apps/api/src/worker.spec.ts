import { NestFactory } from '@nestjs/core';

import { handler } from './worker';

describe('reconciliation worker', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  const application = (result: unknown) => {
    const close = jest.fn().mockResolvedValue(undefined);
    const reconcileDue = jest.fn().mockResolvedValue(result);
    jest.spyOn(NestFactory, 'createApplicationContext').mockResolvedValue({
      close,
      get: jest.fn().mockReturnValue({ reconcileDue }),
    } as never);
    return { close, reconcileDue };
  };

  it('returns PASS and closes the application after reconciliation', async () => {
    const context = application({ ok: true, value: 3 });

    await expect(handler()).resolves.toEqual({ status: 'PASS', reconciled: 3 });
    expect(context.reconcileDue).toHaveBeenCalledTimes(1);
    expect(context.close).toHaveBeenCalledTimes(1);
  });

  it('throws and closes the application when reconciliation fails', async () => {
    const context = application({ ok: false, error: { code: 'INTERNAL_ERROR' } });

    await expect(handler()).rejects.toThrow('RECONCILIATION_FAILED');
    expect(context.close).toHaveBeenCalledTimes(1);
  });
});
