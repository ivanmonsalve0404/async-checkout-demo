import { formatMoney, formatMoneyForAssistiveTechnology } from '../../../shared/lib/format-money';
import type { CheckoutResponse } from '../api/checkout-api';

export interface ReviewStepProps {
  readonly checkout: CheckoutResponse;
  readonly installments: number;
  readonly submitting: boolean;
  readonly onBack: () => void;
  readonly onRefreshQuote: () => void;
  readonly onSubmit: () => void;
  readonly now?: number;
}

export const isQuoteExpired = (expiresAt: string, now = Date.now()): boolean => {
  const parsed = Date.parse(expiresAt);
  return !Number.isFinite(parsed) || parsed <= now;
};

const MoneyRow = ({
  label,
  amountInCents,
  emphasis = false,
}: Readonly<{ label: string; amountInCents: number; emphasis?: boolean }>) => (
  <div className={emphasis ? 'money-row total-row' : 'money-row'}>
    <dt>{label}</dt>
    <dd>
      <span aria-hidden="true">{formatMoney(amountInCents, 'COP')}</span>
      <span className="visually-hidden">
        {formatMoneyForAssistiveTechnology(amountInCents, 'COP')}
      </span>
    </dd>
  </div>
);

export const ReviewStep = ({
  checkout,
  installments,
  submitting,
  onBack,
  onRefreshQuote,
  onSubmit,
  now,
}: ReviewStepProps) => {
  const stale = isQuoteExpired(checkout.quote.expiresAt, now);
  return (
    <section data-testid="checkout-step-review">
      <header className="step-heading">
        <p className="eyebrow">Paso 4 de 5</p>
        <h2 id="checkout-step-title" tabIndex={-1}>
          Revisa y confirma
        </h2>
        <p>El total fue calculado por el servidor para una unidad.</p>
      </header>
      {stale && (
        <div
          className="review-alert"
          role="alert"
          tabIndex={-1}
          data-testid="smk-e5-09-quote-stale"
        >
          <strong>La cotización venció</strong>
          <p>Actualiza el total antes de confirmar. No se enviará ningún pago.</p>
          <button type="button" className="quiet-action" onClick={onRefreshQuote}>
            Actualizar total
          </button>
        </div>
      )}
      <dl className="order-summary">
        <div className="money-row">
          <dt>Producto</dt>
          <dd>{checkout.product.name} × 1</dd>
        </div>
        <MoneyRow label="Subtotal" amountInCents={checkout.quote.subtotal.amountInCents} />
        <MoneyRow label="Tarifa base" amountInCents={checkout.quote.baseFee.amountInCents} />
        <MoneyRow label="Entrega" amountInCents={checkout.quote.deliveryFee.amountInCents} />
        <MoneyRow label="Total" amountInCents={checkout.quote.total.amountInCents} emphasis />
        <div className="money-row">
          <dt>Forma de pago</dt>
          <dd>{installments === 1 ? '1 cuota' : String(installments) + ' cuotas'}</dd>
        </div>
        <div className="money-row">
          <dt>Condiciones</dt>
          <dd>2 aceptaciones confirmadas</dd>
        </div>
      </dl>
      <p className="privacy-note">El método de pago es efímero y no se mostrará ni almacenará.</p>
      <div className="dialog-actions">
        <button className="quiet-action" type="button" onClick={onBack} disabled={submitting}>
          Editar
        </button>
        <button
          className="primary-action"
          type="button"
          onClick={onSubmit}
          disabled={stale || submitting}
          aria-busy={submitting}
          aria-label={
            submitting
              ? 'Creando transacción'
              : 'Pagar ' +
                formatMoneyForAssistiveTechnology(checkout.quote.total.amountInCents, 'COP')
          }
          data-testid="checkout-submit"
        >
          {submitting
            ? 'Creando transacción…'
            : 'Pagar ' + formatMoney(checkout.quote.total.amountInCents, 'COP')}
        </button>
      </div>
    </section>
  );
};
