import { andThen, andThenAsync, err, map, mapError, ok } from './result';

describe('Result', () => {
  it('composes success values', async () => {
    expect(map(ok(2), (value) => value * 2)).toEqual(ok(4));
    expect(andThen(ok(2), (value) => ok(String(value)))).toEqual(ok('2'));
    await expect(andThenAsync(ok(2), async (value) => ok(value + 1))).resolves.toEqual(ok(3));
  });

  it('preserves or maps typed errors', async () => {
    const failure = err('source');
    expect(map(failure, () => 1)).toBe(failure);
    expect(andThen(failure, () => ok(1))).toBe(failure);
    expect(mapError(failure, (error) => error.toUpperCase())).toEqual(err('SOURCE'));
    await expect(andThenAsync(failure, async () => ok(1))).resolves.toBe(failure);
    expect(mapError(ok(1), () => 'unused')).toEqual(ok(1));
  });
});
