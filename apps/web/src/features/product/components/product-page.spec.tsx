import { render, screen } from '@testing-library/react';
import { ProductPage, toViewState } from './product-page';
import type { ProductQueryState } from './product-page';
import { useGetProductQuery } from '../api/product-api';

jest.mock('../api/product-api', () => ({
  useGetProductQuery: jest.fn(),
}));

const mockUseGetProductQuery = jest.mocked(useGetProductQuery);

const query = (overrides: Partial<ProductQueryState>): ProductQueryState => ({
  isLoading: false,
  data: undefined,
  error: undefined,
  refetch: jest.fn(),
  ...overrides,
});

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
    expect(toViewState(query({ error: { status: 404, data: {} } }))).toEqual({ kind: 'not-found' });
    expect(toViewState(query({ error: { status: 'FETCH_ERROR', error: 'offline' } })).kind).toBe(
      'recoverable-error',
    );
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

  it('renders the hook result through the product view', () => {
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

    render(<ProductPage productId="product-demo-001" />);

    expect(screen.getByRole('heading', { name: 'Producto visible' })).toBeVisible();
  });
});
