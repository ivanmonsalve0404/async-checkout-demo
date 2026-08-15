import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { AppErrorBoundary } from './app/error-boundary/app-error-boundary';
import { AppProviders } from './app/providers/app-providers';
import { AppRouter } from './app/router/app-router';
import { readPublicConfig } from './shared/config/public-config';
import './styles.css';

const config = readPublicConfig(import.meta.env);
const container = document.getElementById('root');
if (container === null) {
  throw new Error('Root container is required');
}

createRoot(container).render(
  <StrictMode>
    <AppErrorBoundary>
      <AppProviders>
        <AppRouter defaultProductId={config.productId} />
      </AppProviders>
    </AppErrorBoundary>
  </StrictMode>,
);
