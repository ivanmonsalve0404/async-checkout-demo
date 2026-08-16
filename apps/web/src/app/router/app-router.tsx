import { Navigate, Route, Routes, useParams } from 'react-router-dom';
import { ProductPage, type ProductPageMode } from '../../features/product/components/product-page';
import { checkoutRoutes } from '../../features/checkout/testing-contract';

const ProductRoute = ({ mode }: Readonly<{ mode: ProductPageMode }>) => {
  const { productId } = useParams<{ productId: string }>();
  return productId === undefined ? (
    <Navigate to="/not-found" replace />
  ) : (
    <ProductPage productId={productId} mode={mode} />
  );
};

const NotFound = () => (
  <section className="status-panel" aria-labelledby="route-not-found">
    <h1 id="route-not-found">Página no encontrada</h1>
    <p>La dirección solicitada no existe.</p>
  </section>
);

export const AppRouter = ({ defaultProductId }: Readonly<{ defaultProductId: string }>) => (
  <main id="main-content" className="app-shell">
    <Routes>
      <Route
        path="/"
        element={<Navigate to={checkoutRoutes.product(defaultProductId)} replace />}
      />
      <Route path="/products/:productId" element={<ProductRoute mode="product" />} />
      <Route path="/products/:productId/checkout" element={<ProductRoute mode="capture" />} />
      <Route path="/products/:productId/checkout/status" element={<ProductRoute mode="status" />} />
      <Route path="*" element={<NotFound />} />
    </Routes>
  </main>
);
