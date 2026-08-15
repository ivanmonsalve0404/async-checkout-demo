import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Provider } from 'react-redux';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { createAppStore } from '../../../app/store/store';
import { checkoutRoutes } from '../../checkout/testing-contract';
import { ProductPage, toViewState } from './product-page';
import type { ProductQueryState } from './product-page';
import { useGetProductQuery } from '../api/product-api';

jest.mock('../api/product-api', () => ({
  useGetProductQuery: jest.fn(),
}));

jest.mock('../../checkout/components/checkout-dialog', () => ({
  CheckoutDialog: ({
    onReturn,
    onStatusRoute,
  }: Readonly<{ onReturn: () => void; onStatusRoute: () => void }>) => (
    <>
      <button type="button" data-testid="mock-checkout-return" onClick={onReturn}>
        Volver al producto
      </button>
      <button type="button" data-testid="mock-checkout-status" onClick={onStatusRoute}>
        Ver estado
      </button>
    </>
  ),
}));

const mockUseGetProductQuery = jest.mocked(useGetProductQuery);

const query = (overrides: Partial<ProductQueryState>): ProductQueryState => ({
  isLoading: false,
  data: undefined,
  error: undefined,
  refetch: jest.fn(),
  ...overrides,
});

const LocationProbe = () => {
  const location = useLocation();
  return <output data-testid="location">{location.pathname}</output>;
};

describe('product query state mapping', () => {
  it('maps loading and success', () => {
    expect(toViewState(query({ isLoading: true }))).toEqual({ kind: 'loading' });
    const data = {
      productId: 'product-demo-001',
      sku: 'SKU_1',
      name: 'Producto',
      description: 'Descripción',
      imageUrl: 'http://localhost/product.svg',
      unitPrice: { amountInCents: 100, currency: 'COP' as const },
      available: 1,
    };
    expect(toViewState(query({ data }))).toEqual({ kind: 'success', product: data });
  });

  it('maps 404, network, timeout, and invalid responses', () => {
    const refetch = jest.fn();
    expect(toViewState(query({ error: { status: 404, data: {} } }))).toEqual({ kind: 'not-found' });
    const recoverable = toViewState(
      query({ error: { status: 'FETCH_ERROR', error: 'offline' }, refetch }),
    );
    expect(recoverable.kind).toBe('recoverable-error');
    if (recoverable.kind === 'recoverable-error') {
      recoverable.retry();
    }
    expect(refetch).toHaveBeenCalledTimes(1);
    expect(toViewState(query({ error: { status: 'TIMEOUT_ERROR', error: 'timeout' } })).kind).toBe(
      'recoverable-error',
    );
    expect(
      toViewState(
        query({ error: { status: 'PARSING_ERROR', originalStatus: 200, data: '', error: 'bad' } }),
      ),
    ).toEqual({ kind: 'unrecoverable-error' });
    expect(toViewState(query({ error: null }))).toEqual({ kind: 'unrecoverable-error' });
    expect(toViewState(query({ error: { status: false } }))).toEqual({
      kind: 'unrecoverable-error',
    });
  });

  it('renders the hook result and opens the stable checkout route', async () => {
    const data = {
      productId: 'product-demo-001',
      sku: 'SKU_1',
      name: 'Producto visible',
      description: 'Descripción visible',
      imageUrl: 'http://localhost/product.svg',
      unitPrice: { amountInCents: 100, currency: 'COP' as const },
      available: 1,
    };
    mockUseGetProductQuery.mockReturnValue(query({ data }) as never);

    render(
      <Provider store={createAppStore()}>
        <MemoryRouter>
          <ProductPage productId="product-demo-001" />
          <LocationProbe />
        </MemoryRouter>
      </Provider>,
    );

    expect(screen.getByRole('heading', { name: 'Producto visible' })).toBeVisible();
    await userEvent.click(screen.getByTestId('product-checkout-cta'));
    expect(screen.getByTestId('location')).toHaveTextContent(
      checkoutRoutes.capture('product-demo-001'),
    );
  });

  it('refetches canonical stock and price when checkout returns to the product', async () => {
    const refetch = jest.fn();
    const data = {
      productId: 'product-demo-001',
      sku: 'SKU_1',
      name: 'Producto visible',
      description: 'Descripción visible',
      imageUrl: 'http://localhost/product.svg',
      unitPrice: { amountInCents: 100, currency: 'COP' as const },
      available: 1,
    };
    mockUseGetProductQuery.mockReturnValue(query({ data, refetch }) as never);

    render(
      <Provider store={createAppStore()}>
        <MemoryRouter>
          <ProductPage productId="product-demo-001" mode="capture" />
          <LocationProbe />
        </MemoryRouter>
      </Provider>,
    );

    await userEvent.click(screen.getByTestId('mock-checkout-status'));
    expect(screen.getByTestId('location')).toHaveTextContent(
      checkoutRoutes.status('product-demo-001'),
    );
    await userEvent.click(screen.getByTestId('mock-checkout-return'));

    expect(refetch).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('location')).toHaveTextContent(
      checkoutRoutes.product('product-demo-001'),
    );
  });
});
