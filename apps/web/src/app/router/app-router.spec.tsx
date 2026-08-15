import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { AppRouter } from './app-router';

jest.mock('../../features/product/components/product-page', () => ({
  ProductPage: ({ productId }: Readonly<{ productId: string }>) => <h1>Producto {productId}</h1>,
}));

const renderAt = (path: string) =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <AppRouter defaultProductId="product-demo-001" />
    </MemoryRouter>,
  );

describe('AppRouter', () => {
  it('redirects the root to the configured product', async () => {
    renderAt('/');
    expect(await screen.findByRole('heading', { name: 'Producto product-demo-001' })).toBeVisible();
  });

  it('renders an explicitly requested product', () => {
    renderAt('/products/product-secondary');
    expect(screen.getByRole('heading', { name: 'Producto product-secondary' })).toBeVisible();
  });

  it('renders a safe not-found route', () => {
    renderAt('/ruta-inexistente');
    expect(screen.getByRole('heading', { name: 'Página no encontrada' })).toBeVisible();
  });
});
