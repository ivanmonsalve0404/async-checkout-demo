import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe } from 'jest-axe';
import type { ProductResponse } from '../api/product-api';
import { ProductView } from './product-view';

const product: ProductResponse = {
  productId: 'product-demo-001',
  sku: 'SKU_DEMO_001',
  name: 'Morral urbano de demostración',
  description: 'Producto sintético.',
  imageUrl: 'http://localhost:5173/product-placeholder.svg',
  unitPrice: { amountInCents: 2_500_000, currency: 'COP' },
  available: 3,
};

describe('ProductView', () => {
  it('renders loading accessibly', () => {
    render(<ProductView state={{ kind: 'loading' }} />);
    expect(screen.getByLabelText('Cargando producto')).toHaveAttribute('aria-busy', 'true');
    expect(screen.getByText(/Cargando producto y disponibilidad/)).toBeInTheDocument();
  });

  it('renders API product, price, and stock', () => {
    render(<ProductView state={{ kind: 'success', product }} />);
    expect(screen.getByRole('heading', { name: product.name })).toBeInTheDocument();
    expect(screen.getByText('3 unidades disponibles')).toBeInTheDocument();
    expect(screen.getByLabelText(/Precio/)).toHaveTextContent(/25[.\s]000/);
    expect(screen.getByRole('button', { name: 'Continuar al pago' })).toBeDisabled();
  });

  it('renders out-of-stock copy and disables continuation', () => {
    render(<ProductView state={{ kind: 'success', product: { ...product, available: 0 } }} />);
    expect(screen.getByText('Agotado por ahora')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Sin disponibilidad' })).toBeDisabled();
  });

  it('renders a controlled missing state', () => {
    render(<ProductView state={{ kind: 'not-found' }} />);
    expect(screen.getByRole('heading', { name: 'Producto no disponible' })).toBeInTheDocument();
  });

  it('allows retry after a recoverable error', async () => {
    const retry = jest.fn();
    render(<ProductView state={{ kind: 'recoverable-error', retry }} />);
    await userEvent.click(screen.getByRole('button', { name: 'Reintentar' }));
    expect(retry).toHaveBeenCalledTimes(1);
  });

  it('uses a safe unrecoverable state', () => {
    render(<ProductView state={{ kind: 'unrecoverable-error' }} />);
    expect(screen.getByText(/respuesta recibida no es segura/)).toBeInTheDocument();
  });

  it('has no basic accessibility violations', async () => {
    const { container } = render(<ProductView state={{ kind: 'success', product }} />);
    expect(await axe(container)).toHaveNoViolations();
  });
});
