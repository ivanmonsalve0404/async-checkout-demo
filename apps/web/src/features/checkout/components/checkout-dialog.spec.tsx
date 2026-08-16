import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Provider } from 'react-redux';
import { createAppStore, type AppStore } from '../../../app/store/store';
import {
  useCreateCheckoutMutation,
  useGetCheckoutQuery,
  useGetPaymentConfigurationQuery,
  useGetTransactionQuery,
  useReplaceCustomerMutation,
  useReplaceDeliveryMutation,
  type CheckoutResponse,
  type PaymentConfigurationResponse,
  type TransactionResponse,
} from '../api/checkout-api';
import { checkoutCreated, checkoutRecovered } from '../model/checkout-slice';
import { PaymentCommandError, submitPayment } from '../services/submit-payment';
import { paymentTokenTtlMs } from '../services/use-ephemeral-payment-token';
import { passesLuhn } from '../validation/card-validation';
import { CheckoutDialog } from './checkout-dialog';

jest.mock('../api/checkout-api', () => ({
  useCreateCheckoutMutation: jest.fn(),
  useGetCheckoutQuery: jest.fn(),
  useGetPaymentConfigurationQuery: jest.fn(),
  useGetTransactionQuery: jest.fn(),
  useReplaceCustomerMutation: jest.fn(),
  useReplaceDeliveryMutation: jest.fn(),
}));

jest.mock('../services/submit-payment', () => {
  const actual = jest.requireActual('../services/submit-payment');
  return { ...actual, submitPayment: jest.fn() };
});

const mockCreate = jest.mocked(useCreateCheckoutMutation);
const mockCheckout = jest.mocked(useGetCheckoutQuery);
const mockConfiguration = jest.mocked(useGetPaymentConfigurationQuery);
const mockTransaction = jest.mocked(useGetTransactionQuery);
const mockCustomer = jest.mocked(useReplaceCustomerMutation);
const mockDelivery = jest.mocked(useReplaceDeliveryMutation);
const mockSubmit = jest.mocked(submitPayment);

const money = { amountInCents: 1_000, currency: 'COP' as const };
const checkout: CheckoutResponse = {
  checkoutId: 'checkout_123456',
  status: 'DRAFT',
  version: 1,
  product: {
    productId: 'product_123456',
    sku: 'SKU_1',
    name: 'Producto',
    description: 'Sintético',
    imageUrl: 'http://localhost/product.svg',
    unitPrice: money,
    available: 1,
  },
  quote: {
    quoteId: 'quote_12345678',
    version: 1,
    productId: 'product_123456',
    quantity: 1,
    subtotal: money,
    baseFee: money,
    deliveryFee: money,
    total: { amountInCents: 3_000, currency: 'COP' },
    expiresAt: '2099-01-01T00:00:00Z',
  },
  customer: null,
  deliveryDetails: null,
  activeTransactionId: null,
  expiresAt: '2099-01-01T01:00:00Z',
};
const configuration: PaymentConfigurationResponse = {
  captureVariant: 'FAKE_CONTRACT',
  sandboxPublicKey: 'public-synthetic',
  allowedInstallments: [1, 3],
  acceptanceContracts: [
    {
      type: 'TERMS',
      permalink: 'https://example.test/terms',
      version: 'v1',
      acceptanceToken: 'terms-synthetic',
    },
    {
      type: 'PERSONAL_DATA',
      permalink: 'https://example.test/privacy',
      version: 'v1',
      acceptanceToken: 'privacy-synthetic',
    },
  ],
  expiresAt: '2099-01-01T00:00:00Z',
};
const transaction = (overrides: Partial<TransactionResponse> = {}): TransactionResponse => ({
  transactionId: 'transaction_123456',
  checkoutId: 'checkout_123456',
  checkoutStatus: 'PAID',
  paymentStatus: 'APPROVED',
  dispatchPhase: 'ACKNOWLEDGED',
  providerStatus: 'APPROVED',
  reservationStatus: 'CONSUMED',
  integrityStatus: 'OK',
  statusUrl: '/api/v1/transactions/transaction_123456',
  allowedActions: ['RETURN_TO_PRODUCT'],
  acceptedAt: '2026-01-01T00:00:00Z',
  updatedAt: '2026-01-01T00:00:01Z',
  ...overrides,
});

let checkoutResult: Record<string, unknown>;
let transactionResult: Record<string, unknown>;
let checkoutRefetch: jest.Mock;
let configurationResult: Record<string, unknown>;
let transactionRefetch: jest.Mock;
let configurationRefetch: jest.Mock;
let createTrigger: jest.Mock;
let customerTrigger: jest.Mock;
let deliveryTrigger: jest.Mock;

const configureHooks = (transactionData: TransactionResponse | undefined = undefined): void => {
  checkoutRefetch = jest.fn().mockResolvedValue({ data: checkout });
  transactionRefetch = jest.fn().mockResolvedValue({ data: transactionData });
  configurationRefetch = jest.fn().mockResolvedValue({ data: configuration });
  createTrigger = jest.fn(() => ({
    unwrap: () =>
      Promise.resolve({
        checkoutId: checkout.checkoutId,
        status: 'DRAFT',
        version: checkout.version,
        quote: checkout.quote,
        expiresAt: checkout.expiresAt,
      }),
  }));
  customerTrigger = jest.fn(() => ({
    unwrap: () =>
      Promise.resolve({
        checkoutId: checkout.checkoutId,
        customerId: 'customer_123456',
        version: 2,
        fullName: 'Persona Sintética',
        email: 'persona@example.test',
        phone: '+573000000000',
      }),
  }));
  deliveryTrigger = jest.fn(() => ({
    unwrap: () =>
      Promise.resolve({
        checkoutId: checkout.checkoutId,
        version: 3,
        addressLine1: 'Calle sintética 123',
        city: 'Bogotá',
        region: 'Cundinamarca',
      }),
  }));
  checkoutResult = {
    data: checkout,
    isLoading: false,
    error: undefined,
    refetch: checkoutRefetch,
  };
  transactionResult = {
    data: transactionData,
    isFetching: false,
    isError: false,
    refetch: transactionRefetch,
  };
  mockCreate.mockReturnValue([createTrigger, { isLoading: false }] as never);
  mockCheckout.mockImplementation(() => checkoutResult as never);
  configurationResult = {
    data: configuration,
    isLoading: false,
    isError: false,
    refetch: configurationRefetch,
  };
  mockConfiguration.mockImplementation(() => configurationResult as never);
  mockTransaction.mockImplementation(() => transactionResult as never);
  mockCustomer.mockReturnValue([customerTrigger] as never);
  mockDelivery.mockReturnValue([deliveryTrigger] as never);
  mockSubmit.mockResolvedValue({
    transactionId: 'transaction_123456',
    statusUrl: '/api/v1/transactions/transaction_123456',
    submissionState: 'ACCEPTED',
    acceptedAt: '2026-01-01T00:00:00Z',
  });
};

const renderDialog = (
  mode: 'capture' | 'status' = 'capture',
  prepared = true,
  storeOverride?: AppStore,
): {
  readonly store: AppStore;
  readonly onClose: jest.Mock;
  readonly onStatusRoute: jest.Mock;
  readonly onReturn: jest.Mock;
  readonly rerender: () => void;
  readonly unmount: () => void;
} => {
  const store = storeOverride ?? createAppStore();
  if (prepared) {
    if (mode === 'status') {
      store.dispatch(
        checkoutRecovered({
          checkoutId: checkout.checkoutId,
          transactionId: 'transaction_123456',
          idempotencyKey: 'idem_1234567890123456',
        }),
      );
    } else {
      store.dispatch(
        checkoutCreated({
          checkoutId: checkout.checkoutId,
          idempotencyKey: 'idem_1234567890123456',
        }),
      );
    }
  }
  const onClose = jest.fn();
  const onStatusRoute = jest.fn();
  const onReturn = jest.fn();
  const view = () => (
    <Provider store={store}>
      <button data-testid="product-checkout-cta" type="button">
        Comprar
      </button>
      <div data-testid="product-surface">Producto</div>
      <CheckoutDialog
        productId="product_123456"
        mode={mode}
        onClose={onClose}
        onStatusRoute={onStatusRoute}
        onReturn={onReturn}
      />
    </Provider>
  );
  const rendered = render(view());
  return {
    store,
    onClose,
    onStatusRoute,
    onReturn,
    rerender: () => rendered.rerender(view()),
    unmount: rendered.unmount,
  };
};

const validNumber = (): string => {
  const prefix = '4' + '0'.repeat(14);
  return Array.from({ length: 10 }, (_, value) => prefix + String(value)).find(passesLuhn) ?? '';
};

const syntheticExpiry = (): string => ['12', '99'].join('');
const syntheticSecurityCode = (): string => [8, 7, 3].join('');

const advanceToReview = async (): Promise<void> => {
  await userEvent.type(screen.getByRole('textbox', { name: /Número de tarjeta/ }), validNumber());
  await userEvent.type(screen.getByRole('textbox', { name: /Vencimiento/ }), syntheticExpiry());
  await userEvent.type(
    screen.getByRole('textbox', { name: /Código de seguridad/ }),
    syntheticSecurityCode(),
  );
  await userEvent.type(
    screen.getByRole('textbox', { name: /Nombre en la tarjeta/ }),
    'Persona Sintética',
  );
  await userEvent.click(screen.getByRole('button', { name: 'Continuar' }));
  expect(await screen.findByTestId('checkout-step-customer')).toBeVisible();

  await userEvent.type(
    screen.getByRole('textbox', { name: 'Nombre completo' }),
    'Persona Sintética',
  );
  await userEvent.type(
    screen.getByRole('textbox', { name: 'Correo electrónico' }),
    'persona@example.test',
  );
  await userEvent.type(screen.getByRole('textbox', { name: 'Teléfono' }), '+573000000000');
  await userEvent.type(screen.getByRole('textbox', { name: 'Dirección' }), 'Calle sintética 123');
  await userEvent.type(screen.getByRole('textbox', { name: 'Ciudad' }), 'Bogotá');
  await userEvent.type(
    screen.getByRole('textbox', { name: 'Departamento o región' }),
    'Cundinamarca',
  );
  await userEvent.click(screen.getByRole('button', { name: 'Continuar' }));
  expect(await screen.findByTestId('checkout-step-acceptances')).toBeVisible();

  await userEvent.click(screen.getByRole('checkbox', { name: /términos/ }));
  await userEvent.click(screen.getByRole('checkbox', { name: /tratamiento/ }));
  await userEvent.click(screen.getByRole('button', { name: 'Revisar compra' }));
  expect(await screen.findByTestId('checkout-step-review')).toBeVisible();
};

describe('CheckoutDialog orchestration', () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    configureHooks();
  });

  it('executes the five-step fake checkout and polls only the local transaction', async () => {
    const approved = transaction();
    transactionResult.data = approved;
    const { store, onStatusRoute } = renderDialog();
    await advanceToReview();
    await userEvent.dblClick(screen.getByTestId('checkout-submit'));
    await waitFor(() => expect(mockSubmit).toHaveBeenCalledTimes(1));
    const serializedCommand = JSON.stringify(mockSubmit.mock.calls[0]?.[0]);
    const sensitiveAliases = ['number', 'pan', 'cvc', 'securityCode', 'expiry'];
    const containsSensitiveAlias = sensitiveAliases.some((alias) =>
      new RegExp('"' + alias + '"\\s*:', 'i').test(serializedCommand),
    );
    const sensitiveValues = new Set([validNumber(), syntheticExpiry(), syntheticSecurityCode()]);
    let containsSensitiveValue = false;
    JSON.parse(serializedCommand, (_key, value: unknown) => {
      if (typeof value === 'string' && sensitiveValues.has(value)) containsSensitiveValue = true;
      return value;
    });
    expect(containsSensitiveAlias).toBe(false);
    expect(containsSensitiveValue).toBe(false);
    expect(onStatusRoute).toHaveBeenCalled();
    expect(await screen.findByTestId('transaction-approved')).toBeVisible();
    expect(customerTrigger).toHaveBeenCalledTimes(1);
    expect(deliveryTrigger).toHaveBeenCalledTimes(1);
    await userEvent.click(screen.getByTestId('return-product'));
    expect(store.getState().checkout).toMatchObject({
      checkoutId: undefined,
      transactionId: undefined,
      idempotencyKey: undefined,
      returnNotice: 'APPROVED',
    });
  });

  it('rejects a five-minute-old token and returns to an empty card capture', async () => {
    const capturedAt = Date.parse('2026-01-01T00:00:00Z');
    const now = jest.spyOn(Date, 'now').mockReturnValue(capturedAt);
    try {
      renderDialog();
      await advanceToReview();

      now.mockReturnValue(capturedAt + paymentTokenTtlMs);
      await userEvent.click(screen.getByTestId('checkout-submit'));

      expect(await screen.findByTestId('checkout-step-payment')).toBeVisible();
      expect(screen.getByRole('alert')).toHaveTextContent('método de pago venció');
      expect(screen.getByRole('textbox', { name: /Número de tarjeta/ })).toHaveValue('');
      expect(screen.getByRole('textbox', { name: /Vencimiento/ })).toHaveValue('');
      expect(screen.getByRole('textbox', { name: /Código de seguridad/ })).toHaveValue('');
      expect(screen.getByRole('textbox', { name: /Nombre en la tarjeta/ })).toHaveValue('');
      expect(mockSubmit).not.toHaveBeenCalled();
    } finally {
      now.mockRestore();
    }
  });

  it('reconciles a lost customer response and one delivery 412 without losing the form', async () => {
    const customerSnapshot = {
      checkoutId: checkout.checkoutId,
      customerId: 'customer_123456',
      version: 2,
      fullName: 'Persona Sintética',
      email: 'persona@example.test',
      phone: '+573000000000',
    };
    const customerApplied: CheckoutResponse = {
      ...checkout,
      version: 2,
      customer: customerSnapshot,
    };
    const concurrentSnapshot: CheckoutResponse = {
      ...customerApplied,
      version: 3,
    };
    const readySnapshot: CheckoutResponse = {
      ...concurrentSnapshot,
      status: 'READY',
      version: 4,
      deliveryDetails: {
        checkoutId: checkout.checkoutId,
        version: 4,
        addressLine1: 'Calle sintética 123',
        city: 'Bogotá',
        region: 'Cundinamarca',
      },
    };
    customerTrigger = jest.fn(() => ({
      unwrap: () => Promise.reject(new TypeError('response lost')),
    }));
    deliveryTrigger = jest.fn(({ version }: { readonly version: number }) => ({
      unwrap: () =>
        version === 2
          ? Promise.reject(Object.assign(new Error('precondition failed'), { status: 412 }))
          : Promise.resolve({
              checkoutId: checkout.checkoutId,
              version: 4,
              addressLine1: 'Calle sintética 123',
              city: 'Bogotá',
              region: 'Cundinamarca',
            }),
    }));
    mockCustomer.mockReturnValue([customerTrigger] as never);
    mockDelivery.mockReturnValue([deliveryTrigger] as never);
    checkoutRefetch
      .mockReset()
      .mockResolvedValueOnce({ data: customerApplied })
      .mockResolvedValueOnce({ data: concurrentSnapshot })
      .mockResolvedValueOnce({ data: readySnapshot });

    renderDialog();
    await advanceToReview();

    expect(customerTrigger).toHaveBeenCalledTimes(1);
    expect(deliveryTrigger).toHaveBeenCalledTimes(2);
    expect(deliveryTrigger.mock.calls.map(([request]) => request.version)).toEqual([2, 3]);
    expect(deliveryTrigger.mock.calls[0]?.[0]).toMatchObject({
      body: {
        addressLine1: 'Calle sintética 123',
        city: 'Bogotá',
        region: 'Cundinamarca',
      },
    });
    expect(checkoutRefetch).toHaveBeenCalledTimes(3);
    expect(screen.getByTestId('checkout-step-review')).toBeVisible();
  });

  it('stops RTK polling at a terminal state without waiting', async () => {
    transactionResult.data = transaction();
    renderDialog('status');
    await waitFor(() => {
      const options = mockTransaction.mock.calls.at(-1)?.[1] as { pollingInterval: number };
      expect(options.pollingInterval).toBe(0);
    });
  });

  it('does not renavigate when the canonical transaction is already on the status route', async () => {
    checkoutResult = {
      ...checkoutResult,
      data: { ...checkout, activeTransactionId: 'transaction_123456' },
    };
    transactionResult.data = transaction();
    const { onStatusRoute, rerender } = renderDialog('status');

    expect(await screen.findByTestId('transaction-approved')).toBeVisible();
    rerender();

    expect(onStatusRoute).not.toHaveBeenCalled();
  });
  it('delegates bounded polling outside RTK and renders unknown distinctly', async () => {
    transactionResult.data = transaction({
      checkoutStatus: 'PAYMENT_PENDING',
      paymentStatus: 'PENDING',
      dispatchPhase: 'UNKNOWN',
      providerStatus: null,
      reservationStatus: 'ACTIVE',
      retryAfterSeconds: 7,
      allowedActions: ['QUERY', 'WAIT', 'RETURN_TO_PRODUCT'],
    });
    renderDialog('status');
    expect(await screen.findByTestId('transaction-unknown')).toBeVisible();
    await waitFor(() => {
      const options = mockTransaction.mock.calls.at(-1)?.[1] as { pollingInterval: number };
      expect(options.pollingInterval).toBe(0);
    });
  });

  it.each([
    ['pending', 'ACKNOWLEDGED', 'transaction-pending'],
    ['unknown', 'UNKNOWN', 'transaction-unknown'],
  ] as const)(
    'preserves and reopens the same %s attempt',
    async (_label, dispatchPhase, testId) => {
      const inFlight = transaction({
        checkoutStatus: 'PAYMENT_PENDING',
        paymentStatus: 'PENDING',
        dispatchPhase,
        providerStatus: 'PENDING',
        reservationStatus: 'ACTIVE',
        allowedActions: ['QUERY', 'WAIT', 'RETURN_TO_PRODUCT'],
      });
      configureHooks(inFlight);
      const { store, onReturn } = renderDialog('status');

      await userEvent.click(await screen.findByTestId('return-product'));

      expect(onReturn).toHaveBeenCalledTimes(1);
      expect(store.getState().checkout).toMatchObject({
        checkoutId: 'checkout_123456',
        transactionId: 'transaction_123456',
        idempotencyKey: 'idem_1234567890123456',
        step: 'status',
        modalOpen: false,
      });

      cleanup();
      configureHooks(inFlight);
      renderDialog('status', false, store);

      expect(await screen.findByTestId(testId)).toBeVisible();
      expect(mockTransaction.mock.calls.at(-1)?.[0]).toBe('transaction_123456');
      expect(store.getState().checkout.idempotencyKey).toBe('idem_1234567890123456');
      expect(mockSubmit).not.toHaveBeenCalled();
    },
  );

  it('preserves and reopens an integrity conflict with a safe support reference', async () => {
    const conflicted = transaction({
      paymentStatus: 'APPROVED',
      providerStatus: 'APPROVED',
      reservationStatus: 'ACTIVE',
      integrityStatus: 'APPROVED_INVENTORY_CONFLICT',
      recoveryCode: 'STATE_TRANSITION_CONFLICT',
      allowedActions: ['QUERY', 'RETURN_TO_PRODUCT', 'CONTACT_SUPPORT'],
    });
    configureHooks(conflicted);
    const { store, onReturn } = renderDialog('status');

    expect(await screen.findByTestId('contact-support')).toHaveTextContent('transaction_123456');
    await userEvent.click(screen.getByTestId('return-product'));

    expect(onReturn).toHaveBeenCalledTimes(1);
    expect(store.getState().checkout).toMatchObject({
      checkoutId: 'checkout_123456',
      transactionId: 'transaction_123456',
      idempotencyKey: 'idem_1234567890123456',
      step: 'status',
      modalOpen: false,
      returnNotice: undefined,
    });

    cleanup();
    configureHooks(conflicted);
    renderDialog('status', false, store);

    expect(await screen.findByTestId('transaction-conflict')).toBeVisible();
    expect(mockTransaction.mock.calls.at(-1)?.[0]).toBe('transaction_123456');
    expect(mockSubmit).not.toHaveBeenCalled();
  });

  it('clears a final failed checkout before starting another attempt', async () => {
    transactionResult.data = transaction({
      checkoutStatus: 'PAYMENT_FAILED',
      paymentStatus: 'DECLINED',
      providerStatus: 'DECLINED',
      reservationStatus: 'RELEASED',
      allowedActions: ['START_NEW_CHECKOUT', 'RETURN_TO_PRODUCT'],
    });
    const { store, onClose } = renderDialog('status');
    await userEvent.click(await screen.findByTestId('retry-payment'));
    expect(store.getState().checkout.checkoutId).toBeUndefined();
    expect(store.getState().checkout.idempotencyKey).toBeUndefined();
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('recovers a generic 409 from the canonical active transaction without restarting', async () => {
    const conflicted = transaction({
      paymentStatus: 'APPROVED',
      providerStatus: 'APPROVED',
      reservationStatus: 'ACTIVE',
      integrityStatus: 'FINAL_STATE_CONFLICT',
      recoveryCode: 'STATE_TRANSITION_CONFLICT',
      allowedActions: ['QUERY', 'RETURN_TO_PRODUCT', 'CONTACT_SUPPORT'],
    });
    configureHooks(conflicted);
    checkoutRefetch.mockResolvedValueOnce({ data: checkout }).mockResolvedValue({
      data: { ...checkout, activeTransactionId: 'transaction_123456' },
    });
    mockSubmit.mockRejectedValue(new PaymentCommandError(409));
    const { store, onStatusRoute, onReturn } = renderDialog();

    await advanceToReview();
    await userEvent.click(screen.getByTestId('checkout-submit'));

    expect(await screen.findByTestId('transaction-conflict')).toBeVisible();
    expect(onStatusRoute).toHaveBeenCalledTimes(1);
    expect(onReturn).not.toHaveBeenCalled();
    expect(checkoutRefetch).toHaveBeenCalledTimes(2);
    expect(mockSubmit).toHaveBeenCalledTimes(1);
    expect(screen.queryByTestId('retry-payment')).not.toBeInTheDocument();
    expect(store.getState().checkout).toMatchObject({
      checkoutId: 'checkout_123456',
      transactionId: 'transaction_123456',
      idempotencyKey: 'idem_1234567890123456',
      step: 'status',
    });
  });

  it.each([
    [new PaymentCommandError(409, 'QUOTE_STALE'), 'cleared'],
    [new PaymentCommandError(412, 'PRECONDITION_FAILED'), 'payment'],
    [new PaymentCommandError(422, 'PAYMENT_TOKEN_REJECTED'), 'acceptance-refresh'],
    [new TypeError('network'), 'unknown'],
  ] as const)('recovers safely from submit failure %s', async (failure, expected) => {
    mockSubmit.mockRejectedValue(failure);
    const { store, onClose, onReturn } = renderDialog();
    await advanceToReview();
    await userEvent.click(screen.getByTestId('checkout-submit'));
    if (expected === 'cleared') {
      await waitFor(() => expect(onReturn).toHaveBeenCalled());
      expect(onClose).not.toHaveBeenCalled();
      expect(store.getState().checkout.checkoutId).toBeUndefined();
    } else if (expected === 'payment') {
      expect(await screen.findByTestId('checkout-step-payment')).toBeVisible();
      expect(checkoutRefetch).toHaveBeenCalled();
    } else if (expected === 'acceptance-refresh') {
      expect(await screen.findByTestId('checkout-step-payment')).toBeVisible();
      expect(configurationRefetch).toHaveBeenCalledTimes(1);
    } else {
      expect(await screen.findByTestId('transaction-unknown')).toBeVisible();
      expect(screen.queryByTestId('checkout-submit')).not.toBeInTheDocument();
    }
  });

  it('creates a checkout once and handles missing or expired recovery', async () => {
    renderDialog('capture', false);
    await waitFor(() => expect(createTrigger).toHaveBeenCalledTimes(1));

    cleanup();
    localStorage.clear();
    sessionStorage.clear();
    configureHooks();
    renderDialog('status', false);
    expect(await screen.findByTestId('checkout-expired')).toHaveTextContent('No pudimos recuperar');

    cleanup();
    localStorage.clear();
    sessionStorage.clear();
    configureHooks();
    checkoutResult = {
      data: undefined,
      isLoading: false,
      error: { status: 410 },
      refetch: checkoutRefetch,
    };
    renderDialog('capture');
    expect(await screen.findByTestId('checkout-expired')).toHaveTextContent('sesión venció');
  });

  it('fails closed when checkout creation loses the network and returns safely', async () => {
    createTrigger.mockImplementation(() => ({
      unwrap: () => Promise.reject(new TypeError('synthetic network failure')),
    }));
    const { onReturn } = renderDialog('capture', false);

    expect(await screen.findByTestId('checkout-expired')).toHaveTextContent('Revisa tu conexión');
    await userEvent.click(screen.getByRole('button', { name: 'Volver al producto' }));

    expect(onReturn).toHaveBeenCalledTimes(1);
  });
  it('creates a fresh idempotency key when persistent recovery has no session state', async () => {
    localStorage.setItem(
      'checkout.progress.ids.v1',
      JSON.stringify({ checkoutId: checkout.checkoutId }),
    );
    sessionStorage.clear();
    const recoveredStore = createAppStore();
    renderDialog('capture', false, recoveredStore);
    await waitFor(() =>
      expect(recoveredStore.getState().checkout.idempotencyKey).toMatch(/^idem_[a-f0-9]{36}$/),
    );
    expect(createTrigger).not.toHaveBeenCalled();
  });

  it('moves focus as the asynchronous checkout surfaces resolve', async () => {
    checkoutResult = {
      data: undefined,
      isLoading: true,
      error: undefined,
      refetch: checkoutRefetch,
    };
    configurationResult = {
      data: undefined,
      isLoading: true,
      isError: false,
      refetch: configurationRefetch,
    };
    const { rerender } = renderDialog();
    await waitFor(() =>
      expect(screen.getByRole('heading', { name: 'Preparando checkout' })).toHaveFocus(),
    );

    checkoutResult = {
      data: checkout,
      isLoading: false,
      error: undefined,
      refetch: checkoutRefetch,
    };
    rerender();
    await waitFor(() =>
      expect(screen.getByRole('heading', { name: 'Preparando método de pago' })).toHaveFocus(),
    );

    configurationResult = {
      data: configuration,
      isLoading: false,
      isError: false,
      refetch: configurationRefetch,
    };
    rerender();
    await waitFor(() =>
      expect(screen.getByRole('heading', { name: 'Método de pago' })).toHaveFocus(),
    );
  });

  it('traps focus, closes with Escape, and restores the launcher', async () => {
    const { onClose, unmount } = renderDialog();
    const close = screen.getByRole('button', { name: 'Cerrar checkout' });
    close.focus();
    await userEvent.keyboard('{Tab}');
    expect(document.activeElement).not.toBe(document.body);
    await userEvent.keyboard('{Escape}');
    expect(onClose).toHaveBeenCalledTimes(1);
    unmount();
    render(<button data-testid="product-checkout-cta">Comprar</button>);
    await waitFor(() => expect(screen.getByTestId('product-checkout-cta')).toHaveFocus());
  });
});
