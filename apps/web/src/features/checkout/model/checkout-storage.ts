import {
  checkoutSteps,
  initialCheckoutState,
  type CheckoutStep,
  type CheckoutUiState,
} from './checkout-slice';

export interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export interface ProgressStores {
  readonly persistent: StorageLike;
  readonly session: StorageLike;
}

const IDS_KEY = 'checkout.progress.ids.v1';
const SESSION_KEY = 'checkout.progress.session.v1';
const opaqueIdPattern = /^[A-Za-z0-9_-]{8,128}$/;
const idempotencyPattern = /^[A-Za-z0-9._~-]{16,128}$/;

const parseObject = (value: string | null): Record<string, unknown> | undefined => {
  if (value === null) {
    return {};
  }
  try {
    const parsed: unknown = JSON.parse(value);
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
};

const hasOnlyKeys = (value: Record<string, unknown>, keys: readonly string[]): boolean =>
  Object.keys(value).every((key) => keys.includes(key));

const validOptional = (value: unknown, pattern: RegExp): value is string | undefined =>
  value === undefined || (typeof value === 'string' && pattern.test(value));

const clearStores = (stores: ProgressStores): void => {
  try {
    stores.persistent.removeItem(IDS_KEY);
    stores.session.removeItem(SESSION_KEY);
  } catch {
    // Storage can be unavailable in privacy modes; canonical state remains on the server.
  }
};

export const readCheckoutProgress = (stores: ProgressStores): CheckoutUiState => {
  try {
    const ids = parseObject(stores.persistent.getItem(IDS_KEY));
    const session = parseObject(stores.session.getItem(SESSION_KEY));
    const step = session?.step;
    if (
      ids === undefined ||
      session === undefined ||
      !hasOnlyKeys(ids, ['checkoutId', 'transactionId']) ||
      !hasOnlyKeys(session, ['step', 'idempotencyKey']) ||
      !validOptional(ids.checkoutId, opaqueIdPattern) ||
      !validOptional(ids.transactionId, opaqueIdPattern) ||
      !validOptional(session.idempotencyKey, idempotencyPattern) ||
      (step !== undefined && !checkoutSteps.includes(step as CheckoutStep)) ||
      (ids.transactionId !== undefined && ids.checkoutId === undefined)
    ) {
      clearStores(stores);
      return { ...initialCheckoutState };
    }
    return {
      ...initialCheckoutState,
      checkoutId: ids.checkoutId,
      transactionId: ids.transactionId,
      idempotencyKey: session.idempotencyKey,
      step: (step as CheckoutStep | undefined) ?? 'payment',
    };
  } catch {
    return { ...initialCheckoutState };
  }
};

export const persistCheckoutProgress = (state: CheckoutUiState, stores: ProgressStores): void => {
  try {
    if (state.checkoutId === undefined) {
      clearStores(stores);
      return;
    }
    const ids: Record<string, string> = { checkoutId: state.checkoutId };
    if (state.transactionId !== undefined) {
      ids.transactionId = state.transactionId;
    }
    const session: Record<string, string> = { step: state.step };
    if (state.idempotencyKey !== undefined) {
      session.idempotencyKey = state.idempotencyKey;
    }
    stores.persistent.setItem(IDS_KEY, JSON.stringify(ids));
    stores.session.setItem(SESSION_KEY, JSON.stringify(session));
  } catch {
    // A blocked storage API must not break checkout; recovery still uses the server when possible.
  }
};

export const browserProgressStores = (): ProgressStores | undefined =>
  typeof window === 'undefined'
    ? undefined
    : { persistent: window.localStorage, session: window.sessionStorage };
