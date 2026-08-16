import {
  persistCheckoutProgress,
  readCheckoutProgress,
  type ProgressStores,
  type StorageLike,
} from './checkout-storage';
import { initialCheckoutState } from './checkout-slice';

class MemoryStorage implements StorageLike {
  public readonly values = new Map<string, string>();
  public getItem(key: string): string | null {
    return this.values.get(key) ?? null;
  }
  public setItem(key: string, value: string): void {
    this.values.set(key, value);
  }
  public removeItem(key: string): void {
    this.values.delete(key);
  }
}

const stores = (): ProgressStores => ({
  persistent: new MemoryStorage(),
  session: new MemoryStorage(),
});

describe('checkout progress allowlist', () => {
  it('persists only opaque IDs and step while keeping the idempotency key in memory', () => {
    const storage = stores();
    persistCheckoutProgress(
      {
        ...initialCheckoutState,
        checkoutId: 'checkout_123456',
        transactionId: 'transaction_123456',
        idempotencyKey: 'idem_1234567890123456',
        step: 'status',
        modalOpen: true,
        returnNotice: 'APPROVED',
      },
      storage,
    );
    const serialized = [
      ...(storage.persistent as MemoryStorage).values.values(),
      ...(storage.session as MemoryStorage).values.values(),
    ].join(' ');
    expect(serialized).toContain('checkout_123456');
    expect(serialized).toContain('transaction_123456');
    expect(serialized).toContain('status');
    expect(serialized).not.toContain('idempotencyKey');
    expect(serialized).not.toContain('idem_1234567890123456');
    expect(serialized).not.toContain('APPROVED');
    expect(serialized).not.toMatch(/email|address|amount/i);
    expect(readCheckoutProgress(storage)).toMatchObject({
      checkoutId: 'checkout_123456',
      transactionId: 'transaction_123456',
      idempotencyKey: undefined,
      step: 'status',
      modalOpen: false,
    });
  });

  it.each([
    ['invalid json', '{'],
    ['unknown key', '{"checkoutId":"checkout_123456","email":"x"}'],
    ['malformed id', '{"checkoutId":"bad/id"}'],
  ])('clears corrupt persistent state: %s', (_label, value) => {
    const storage = stores();
    storage.persistent.setItem('checkout.progress.ids.v1', value);
    expect(readCheckoutProgress(storage)).toEqual(initialCheckoutState);
    expect(storage.persistent.getItem('checkout.progress.ids.v1')).toBeNull();
  });

  it('clears orphaned transaction and all progress after completion', () => {
    const storage = stores();
    storage.persistent.setItem(
      'checkout.progress.ids.v1',
      JSON.stringify({ transactionId: 'transaction_123456' }),
    );
    expect(readCheckoutProgress(storage)).toEqual(initialCheckoutState);

    persistCheckoutProgress(initialCheckoutState, storage);
    expect((storage.persistent as MemoryStorage).values.size).toBe(0);
    expect((storage.session as MemoryStorage).values.size).toBe(0);
  });

  it('fails open for UI when browser storage is unavailable', () => {
    const unavailable: StorageLike = {
      getItem: () => {
        throw new Error('blocked');
      },
      setItem: () => {
        throw new Error('blocked');
      },
      removeItem: () => {
        throw new Error('blocked');
      },
    };
    const storage = { persistent: unavailable, session: unavailable };
    expect(readCheckoutProgress(storage)).toEqual(initialCheckoutState);
    expect(() => persistCheckoutProgress(initialCheckoutState, storage)).not.toThrow();
  });
});
