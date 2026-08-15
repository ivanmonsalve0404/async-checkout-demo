import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type {
  CheckoutResponse,
  PaymentConfigurationResponse,
  TransactionResponse,
} from '../api/checkout-api';
import { AcceptancesStep } from './acceptances-step';
import { ReviewStep } from './review-step';
import { TransactionStep, transactionPresentation } from './transaction-step';

const money = { amountInCents: 1_000, currency: 'COP' as const };
const checkout: CheckoutResponse = {
  checkoutId: 'checkout_123456',
  status: 'READY',
  version: 3,
  product: {
    productId: 'product_123456',
    sku: 'SKU_1',
    name: 'Producto sintético',
    description: 'Descripción',
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
  checkoutStatus: 'PAYMENT_PENDING',
  paymentStatus: 'PENDING',
  dispatchPhase: 'ACKNOWLEDGED',
  providerStatus: 'PENDING',
  reservationStatus: 'ACTIVE',
  integrityStatus: 'OK',
  statusUrl: '/api/v1/transactions/transaction_123456',
  allowedActions: ['QUERY', 'WAIT', 'RETURN_TO_PRODUCT'],
  acceptedAt: '2026-01-01T00:00:00Z',
  updatedAt: '2026-01-01T00:00:01Z',
  ...overrides,
});

describe('acceptance, review, and transaction steps', () => {
  it('requires two independent acceptances and returns only their opaque tokens', async () => {
    const onContinue = jest.fn();
    render(
      <AcceptancesStep configuration={configuration} onBack={jest.fn()} onContinue={onContinue} />,
    );
    await userEvent.click(screen.getByRole('button', { name: 'Revisar compra' }));
    expect(screen.getByRole('alert')).toHaveTextContent('dos condiciones');
    const links = screen.getAllByRole('link');
    expect(links).toHaveLength(2);
    expect(links[0]).toHaveAttribute('rel', 'noopener noreferrer');
    await userEvent.click(screen.getByRole('checkbox', { name: /términos/ }));
    await userEvent.click(screen.getByRole('checkbox', { name: /tratamiento/ }));
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Número de cuotas' }), '3');
    await userEvent.click(screen.getByRole('button', { name: 'Revisar compra' }));
    expect(onContinue).toHaveBeenCalledWith({
      installments: 3,
      termsAcceptanceToken: 'terms-synthetic',
      personalDataAcceptanceToken: 'privacy-synthetic',
    });
  });

  it('renders the server breakdown and blocks an expired quote', async () => {
    const onSubmit = jest.fn();
    const { rerender } = render(
      <ReviewStep
        checkout={checkout}
        installments={1}
        submitting={false}
        onBack={jest.fn()}
        onRefreshQuote={jest.fn()}
        onSubmit={onSubmit}
        now={0}
      />,
    );
    expect(screen.getByText('Tarifa base')).toBeVisible();
    expect(screen.getByRole('button', { name: /Pagar/ })).toBeEnabled();
    await userEvent.click(screen.getByRole('button', { name: /Pagar/ }));
    expect(onSubmit).toHaveBeenCalledTimes(1);

    rerender(
      <ReviewStep
        checkout={checkout}
        installments={1}
        submitting={false}
        onBack={jest.fn()}
        onRefreshQuote={jest.fn()}
        onSubmit={onSubmit}
        now={Date.parse('2100-01-01T00:00:00Z')}
      />,
    );
    expect(screen.getByTestId('smk-e5-09-quote-stale')).toBeVisible();
    expect(screen.getByRole('button', { name: /Pagar/ })).toBeDisabled();
  });

  it.each([
    ['pending', {}, 'Estamos procesando'],
    ['unknown', { dispatchPhase: 'UNKNOWN' }, 'Seguimos verificando'],
    [
      'approved',
      {
        paymentStatus: 'APPROVED',
        checkoutStatus: 'PAID',
        reservationStatus: 'CONSUMED',
        providerStatus: 'APPROVED',
        deliveryId: 'delivery_123456',
      },
      'Pago aprobado',
    ],
    [
      'declined',
      {
        paymentStatus: 'DECLINED',
        checkoutStatus: 'PAYMENT_FAILED',
        reservationStatus: 'RELEASED',
        providerStatus: 'DECLINED',
        allowedActions: ['START_NEW_CHECKOUT', 'RETURN_TO_PRODUCT'],
      },
      'Pago declinado',
    ],
    [
      'error',
      {
        paymentStatus: 'ERROR',
        checkoutStatus: 'PAYMENT_FAILED',
        reservationStatus: 'RELEASED',
        providerStatus: 'ERROR',
      },
      'no pudo completarse',
    ],
    [
      'voided',
      {
        paymentStatus: 'VOIDED',
        checkoutStatus: 'PAYMENT_FAILED',
        reservationStatus: 'RELEASED',
        providerStatus: 'VOIDED',
      },
      'Pago anulado',
    ],
    [
      'conflict',
      {
        paymentStatus: 'APPROVED',
        providerStatus: 'APPROVED',
        integrityStatus: 'APPROVED_INVENTORY_CONFLICT',
      },
      'Necesitamos revisar',
    ],
  ] as const)('maps and renders %s safely', (_expected, overrides, title) => {
    const value = transaction(overrides as Partial<TransactionResponse>);
    expect(transactionPresentation(value)).toBe(_expected);
    render(
      <TransactionStep
        transaction={value}
        loading={false}
        error={false}
        onRefresh={jest.fn()}
        onReturn={jest.fn()}
        onRetry={jest.fn()}
      />,
    );
    expect(screen.getByRole('heading')).toHaveTextContent(title);
  });

  it('returns the canonical approved result to the product', async () => {
    const onReturn = jest.fn();
    render(
      <TransactionStep
        transaction={transaction({
          paymentStatus: 'APPROVED',
          checkoutStatus: 'PAID',
          reservationStatus: 'CONSUMED',
          providerStatus: 'APPROVED',
          deliveryId: 'delivery_123456',
          allowedActions: ['RETURN_TO_PRODUCT'],
        })}
        loading={false}
        error={false}
        onRefresh={jest.fn()}
        onReturn={onReturn}
        onRetry={jest.fn()}
      />,
    );

    await userEvent.click(screen.getByTestId('return-product'));

    expect(onReturn).toHaveBeenCalledWith(true);
  });

  it('offers only GET recovery on loading and network errors', async () => {
    const refresh = jest.fn();
    const { rerender } = render(
      <TransactionStep
        transaction={undefined}
        loading
        error={false}
        onRefresh={refresh}
        onReturn={jest.fn()}
        onRetry={jest.fn()}
      />,
    );
    expect(screen.getByRole('heading')).toHaveTextContent('Consultando');
    rerender(
      <TransactionStep
        transaction={undefined}
        loading={false}
        error
        onRefresh={refresh}
        onReturn={jest.fn()}
        onRetry={jest.fn()}
      />,
    );
    await userEvent.click(screen.getByRole('button', { name: 'Consultar estado' }));
    expect(refresh).toHaveBeenCalledTimes(1);
  });
});
