import type { TransactionResponse } from '../api/checkout-api';

export type TransactionPresentation =
  'pending' | 'unknown' | 'approved' | 'declined' | 'error' | 'voided' | 'conflict';

export const transactionPresentation = (
  transaction: TransactionResponse,
): TransactionPresentation => {
  if (transaction.integrityStatus !== 'OK') {
    return 'conflict';
  }
  if (transaction.paymentStatus === 'PENDING') {
    return transaction.dispatchPhase === 'UNKNOWN' ? 'unknown' : 'pending';
  }
  return transaction.paymentStatus.toLowerCase() as Exclude<
    TransactionPresentation,
    'pending' | 'unknown' | 'conflict'
  >;
};

const copy: Record<TransactionPresentation, Readonly<{ title: string; detail: string }>> = {
  pending: {
    title: 'Estamos procesando tu pago',
    detail: 'La transacción local ya existe. Consultaremos su estado sin repetir el cobro.',
  },
  unknown: {
    title: 'Seguimos verificando',
    detail:
      'Todavía no podemos confirmar el resultado. Tu reserva se conserva y no debes pagar otra vez.',
  },
  approved: {
    title: 'Pago aprobado',
    detail: 'El pago fue confirmado y la entrega fue registrada.',
  },
  declined: {
    title: 'Pago declinado',
    detail: 'No se consumió inventario ni se creó una entrega. Puedes intentar de nuevo.',
  },
  error: {
    title: 'El pago no pudo completarse',
    detail: 'La reserva fue liberada y no se creó una entrega.',
  },
  voided: {
    title: 'Pago anulado',
    detail: 'No se creó una entrega. Vuelve al producto o contacta soporte.',
  },
  conflict: {
    title: 'Necesitamos revisar tu compra',
    detail:
      'Conservamos el resultado del pago sin aplicar efectos adicionales. No intentes pagar otra vez.',
  },
};

export interface TransactionStepProps {
  readonly transaction: TransactionResponse | undefined;
  readonly loading: boolean;
  readonly error: boolean;
  readonly onRefresh: () => void;
  readonly onReturn: (approved: boolean) => void;
  readonly onRetry: () => void;
}

export const TransactionStep = ({
  transaction,
  loading,
  error,
  onRefresh,
  onReturn,
  onRetry,
}: TransactionStepProps) => {
  if (loading && transaction === undefined) {
    return (
      <section
        className="transaction-panel"
        role="status"
        aria-live="polite"
        aria-busy="true"
        data-testid="checkout-step-status"
      >
        <p className="eyebrow">Paso 5 de 5</p>
        <h2 id="checkout-step-title" tabIndex={-1}>
          Consultando la transacción
        </h2>
        <p>Recuperando el estado canónico…</p>
      </section>
    );
  }
  if (error || transaction === undefined) {
    return (
      <section className="transaction-panel" role="alert" data-testid="transaction-network-error">
        <p className="eyebrow">Paso 5 de 5</p>
        <h2 id="checkout-step-title" tabIndex={-1}>
          No pudimos consultar el estado
        </h2>
        <p>No asumiremos que el pago falló. Reintenta únicamente esta consulta.</p>
        <button className="primary-action" type="button" onClick={onRefresh}>
          Consultar estado
        </button>
      </section>
    );
  }

  const presentation = transactionPresentation(transaction);
  const final = !['pending', 'unknown'].includes(presentation);
  const approved = presentation === 'approved';
  const canRetry = transaction.allowedActions.includes('START_NEW_CHECKOUT');
  return (
    <section
      className={'transaction-panel transaction-' + presentation}
      role={presentation === 'conflict' ? 'alert' : 'status'}
      aria-live={final ? 'off' : 'polite'}
      data-testid={'transaction-' + presentation}
    >
      <p className="eyebrow">Paso 5 de 5</p>
      <h2 id="checkout-step-title" tabIndex={-1}>
        {copy[presentation].title}
      </h2>
      <p>{copy[presentation].detail}</p>
      {approved && transaction.deliveryId !== undefined && (
        <p className="success-text">Entrega confirmada.</p>
      )}
      {!final && (
        <button className="primary-action" type="button" onClick={onRefresh} disabled={loading}>
          {loading ? 'Consultando…' : 'Consultar estado'}
        </button>
      )}
      {canRetry && (
        <button
          className="quiet-action"
          type="button"
          onClick={onRetry}
          data-testid="retry-payment"
        >
          Intentar con otro método
        </button>
      )}
      {transaction.allowedActions.includes('RETURN_TO_PRODUCT') && (
        <button
          className={final ? 'primary-action' : 'quiet-action'}
          type="button"
          onClick={() => onReturn(approved)}
          data-testid="return-product"
        >
          Volver al producto
        </button>
      )}
    </section>
  );
};
