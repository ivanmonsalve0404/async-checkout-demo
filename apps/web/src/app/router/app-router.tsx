import { Navigate, Route, Routes, useParams } from 'react-router-dom';
import { ProductPage } from '../../features/product/components/product-page';

const ProductRoute = () => {
  const { productId } = useParams<{ productId: string }>();
  return productId === undefined ? (
    <Navigate to="/not-found" replace />
  ) : (
    <ProductPage productId={productId} />
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
      <Route path="/" element={<Navigate to={`/products/${defaultProductId}`} replace />} />
      <Route path="/products/:productId" element={<ProductRoute />} />
      <Route path="*" element={<NotFound />} />
    </Routes>
  </main>
);
