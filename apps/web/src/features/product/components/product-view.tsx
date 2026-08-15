import type { ProductResponse } from '../api/product-api';
import { formatMoney } from '../../../shared/lib/format-money';

export type ProductViewState =
  | Readonly<{ kind: 'loading' }>
  | Readonly<{ kind: 'success'; product: ProductResponse }>
  | Readonly<{ kind: 'not-found' }>
  | Readonly<{ kind: 'recoverable-error'; retry: () => void }>
  | Readonly<{ kind: 'unrecoverable-error' }>;

export interface ProductViewProps {
  readonly state: ProductViewState;
}

const StatusPanel = ({ title, message }: Readonly<{ title: string; message: string }>) => (
  <section className="status-panel" aria-labelledby="status-title">
    <h1 id="status-title">{title}</h1>
    <p>{message}</p>
  </section>
);

export const ProductView = ({ state }: ProductViewProps) => {
  if (state.kind === 'loading') {
    return (
      <section className="product-card" aria-busy="true" aria-label="Cargando producto">
        <div className="skeleton product-media" />
        <div className="product-copy" role="status" aria-live="polite">
          <span className="skeleton skeleton-line" />
          <span className="skeleton skeleton-line short" />
          <span className="visually-hidden">Cargando producto y disponibilidad…</span>
        </div>
      </section>
    );
  }

  if (state.kind === 'not-found') {
    return (
      <StatusPanel
        title="Producto no disponible"
        message="No encontramos este producto. Revisa el enlace o vuelve al catálogo."
      />
    );
  }

  if (state.kind === 'recoverable-error') {
    return (
      <section className="status-panel danger" aria-labelledby="status-title" role="alert">
        <h1 id="status-title">No pudimos cargar el producto</h1>
        <p>La conexión falló temporalmente. Puedes intentarlo de nuevo.</p>
        <button className="secondary-action" type="button" onClick={state.retry}>
          Reintentar
        </button>
      </section>
    );
  }

  if (state.kind === 'unrecoverable-error') {
    return (
      <StatusPanel
        title="Ocurrió un problema"
        message="La respuesta recibida no es segura para mostrar. Intenta más tarde."
      />
    );
  }

  const { product } = state;
  const isOutOfStock = product.available === 0;
  return (
    <article className="product-card" aria-labelledby="product-title">
      <div className="product-media">
        <img src={product.imageUrl} alt={product.name} width="800" height="600" />
      </div>
      <div className="product-copy">
        <p className="eyebrow">Producto seleccionado</p>
        <h1 id="product-title">{product.name}</h1>
        <p className="description">{product.description}</p>
        <p
          className="price"
          aria-label={`Precio ${formatMoney(product.unitPrice.amountInCents, product.unitPrice.currency)}`}
        >
          {formatMoney(product.unitPrice.amountInCents, product.unitPrice.currency)}
        </p>
        <p className={isOutOfStock ? 'stock danger-text' : 'stock success-text'} aria-live="polite">
          {isOutOfStock ? 'Agotado por ahora' : `${product.available} unidades disponibles`}
        </p>
        <button
          className="primary-action"
          type="button"
          disabled
          aria-describedby="foundation-note"
        >
          {isOutOfStock ? 'Sin disponibilidad' : 'Continuar al pago'}
        </button>
        <p id="foundation-note" className="foundation-note">
          El checkout se habilitará en la etapa 5. Esta vista no captura datos de pago.
        </p>
      </div>
    </article>
  );
};
