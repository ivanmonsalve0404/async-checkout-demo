import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { loadRuntimePublicConfig } from './shared/config/public-config';
import './styles.css';

import './features/checkout/components/checkout.css';
const container = document.getElementById('root');
if (container === null) {
  throw new Error('Root container is required');
}

const root = createRoot(container);

const bootstrap = async (): Promise<void> => {
  const config = await loadRuntimePublicConfig();
  const [{ AppErrorBoundary }, { AppProviders }, { AppRouter }] = await Promise.all([
    import('./app/error-boundary/app-error-boundary'),
    import('./app/providers/app-providers'),
    import('./app/router/app-router'),
  ]);
  root.render(
    <StrictMode>
      <AppErrorBoundary>
        <AppProviders>
          <AppRouter defaultProductId={config.productId} />
        </AppProviders>
      </AppErrorBoundary>
    </StrictMode>,
  );
};

void bootstrap().catch(() => {
  root.render(
    <main role="alert">
      <h1>No pudimos iniciar la compra</h1>
      <p>La configuración pública no está disponible. Intenta nuevamente más tarde.</p>
    </main>,
  );
});
