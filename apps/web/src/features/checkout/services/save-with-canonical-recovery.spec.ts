import { saveWithCanonicalRecovery } from './save-with-canonical-recovery';

interface Canonical {
  readonly version: number;
  readonly value?: string;
}

describe('conditional PUT recovery', () => {
  it('recognises a committed snapshot after the response is lost', async () => {
    const save = jest.fn().mockRejectedValue(new TypeError('response lost'));
    const refetch = jest.fn().mockResolvedValue({ data: { version: 2, value: 'applied' } });

    await expect(
      saveWithCanonicalRecovery<Canonical>(
        1,
        save,
        refetch,
        (current) => current.value === 'applied',
      ),
    ).resolves.toBe(2);
    expect(save).toHaveBeenCalledTimes(1);
  });

  it('retries once with the canonical ETag after a 412', async () => {
    const save = jest
      .fn()
      .mockRejectedValueOnce({ status: 412 })
      .mockResolvedValueOnce({ version: 3 });
    const refetch = jest.fn().mockResolvedValue({ data: { version: 2 } });

    await expect(
      saveWithCanonicalRecovery<Canonical>(
        1,
        save,
        refetch,
        (current) => current.value === 'applied',
      ),
    ).resolves.toBe(3);
    expect(save.mock.calls.map(([version]) => version)).toEqual([1, 2]);
  });

  it('reconciles a lost retry response and never submits a third PUT', async () => {
    const save = jest
      .fn()
      .mockRejectedValueOnce({ status: 412 })
      .mockRejectedValueOnce(new TypeError('retry response lost'));
    const refetch = jest
      .fn()
      .mockResolvedValueOnce({ data: { version: 2 } })
      .mockResolvedValueOnce({ data: { version: 3, value: 'applied' } });

    await expect(
      saveWithCanonicalRecovery<Canonical>(
        1,
        save,
        refetch,
        (current) => current.value === 'applied',
      ),
    ).resolves.toBe(3);
    expect(save).toHaveBeenCalledTimes(2);
  });

  it('does not retry a definitive validation failure', async () => {
    const validationError = Object.assign(new Error('invalid customer'), { status: 422 });
    const save = jest.fn().mockRejectedValue(validationError);
    const refetch = jest.fn().mockResolvedValue({ data: { version: 2 } });

    await expect(
      saveWithCanonicalRecovery<Canonical>(
        1,
        save,
        refetch,
        (current) => current.value === 'applied',
      ),
    ).rejects.toBe(validationError);
    expect(save).toHaveBeenCalledTimes(1);
  });

  it('keeps the original failure when canonical state cannot be read', async () => {
    const responseLost = new TypeError('response lost');
    const save = jest.fn().mockRejectedValue(responseLost);
    const refetch = jest.fn().mockResolvedValue({ data: undefined });

    await expect(
      saveWithCanonicalRecovery<Canonical>(
        1,
        save,
        refetch,
        (current) => current.value === 'applied',
      ),
    ).rejects.toBe(responseLost);
    expect(save).toHaveBeenCalledTimes(1);
  });
});
