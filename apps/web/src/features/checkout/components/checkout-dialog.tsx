import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import { baseApi } from '../../../app/api/base-api';
import { useAppDispatch, useAppSelector } from '../../../app/store/store';
import {
  useCreateCheckoutMutation,
  useGetCheckoutQuery,
  useGetPaymentConfigurationQuery,
  useGetTransactionQuery,
  useReplaceCustomerMutation,
  useReplaceDeliveryMutation,
  type CustomerRequest,
  type DeliveryRequest,
} from '../api/checkout-api';
import {
  checkoutCreated,
  checkoutRecovered,
  closeCheckout,
  createIdempotencyKey,
  progressCleared,
  returnedToProduct,
  stepChanged,
  transactionAccepted,
} from '../model/checkout-slice';
import { selectTokenizationAdapter } from '../services/payment-tokenization';
import { PaymentCommandError, submitPayment } from '../services/submit-payment';
import { AcceptancesStep, type PaymentSelection } from './acceptances-step';
import { CardStep } from './card-step';
import { CustomerDeliveryStep } from './customer-delivery-step';
import { ReviewStep } from './review-step';
import { TransactionStep } from './transaction-step';

export interface CheckoutDialogProps {
  readonly productId: string;
  readonly mode: 'capture' | 'status';
  readonly onClose: () => void;
  readonly onStatusRoute: () => void;
  readonly onReturn: () => void;
}

const readErrorStatus = (error: unknown): number | undefined => {
  if (typeof error !== 'object' || error === null || !('status' in error)) {
    return undefined;
  }
  return typeof error.status === 'number' ? error.status : undefined;
};

const focusableSelector =
  'button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

export const CheckoutDialog = ({
  productId,
  mode,
  onClose,
  onStatusRoute,
  onReturn,
}: CheckoutDialogProps) => {
  const dispatch = useAppDispatch();
  const progress = useAppSelector((state) => state.checkout);
  const [createCheckout, createState] = useCreateCheckoutMutation();
  const [replaceCustomer] = useReplaceCustomerMutation();
  const [replaceDelivery] = useReplaceDeliveryMutation();
  const checkoutQuery = useGetCheckoutQuery(progress.checkoutId ?? '', {
    skip: progress.checkoutId === undefined,
    refetchOnMountOrArgChange: true,
  });
  const configurationQuery = useGetPaymentConfigurationQuery(undefined, {
    skip: progress.step === 'status',
    refetchOnMountOrArgChange: true,
  });
  const [pollingInterval, setPollingInterval] = useState(1_500);
  const transactionQuery = useGetTransactionQuery(progress.transactionId ?? '', {
    skip: progress.transactionId === undefined,
    pollingInterval: progress.transactionId === undefined ? 0 : pollingInterval,
    refetchOnFocus: true,
    refetchOnReconnect: true,
    refetchOnMountOrArgChange: true,
  });
  const dialogRef = useRef<HTMLDivElement>(null);
  const startedRef = useRef(false);
  const paymentTokenRef = useRef<string | undefined>(undefined);
  const selectionRef = useRef<PaymentSelection | undefined>(undefined);
  const [submitting, setSubmitting] = useState(false);
  const [recoveryError, setRecoveryError] = useState<'missing' | 'expired' | 'network'>();
  const [submissionUncertain, setSubmissionUncertain] = useState(false);

  const paymentAdapter = useMemo(
    () =>
      configurationQuery.data === undefined
        ? undefined
        : selectTokenizationAdapter(configurationQuery.data.captureVariant),
    [configurationQuery.data],
  );

  useEffect(() => {
    if (startedRef.current) {
      return;
    }
    startedRef.current = true;
    if (progress.checkoutId !== undefined) {
      dispatch(
        checkoutRecovered({
          checkoutId: progress.checkoutId,
          ...(progress.transactionId === undefined
            ? { idempotencyKey: progress.idempotencyKey ?? createIdempotencyKey() }
            : { transactionId: progress.transactionId }),
        }),
      );
      return;
    }
    if (mode === 'status') {
      setRecoveryError('missing');
      return;
    }
    void createCheckout(productId)
      .unwrap()
      .then((created) => {
        dispatch(
          checkoutCreated({
            checkoutId: created.checkoutId,
            idempotencyKey: createIdempotencyKey(),
          }),
        );
      })
      .catch(() => setRecoveryError('network'));
  }, [createCheckout, dispatch, mode, productId, progress.checkoutId, progress.transactionId]);

  useEffect(() => {
    const checkout = checkoutQuery.data;
    if (checkout === undefined) {
      return;
    }
    if (checkout.status === 'EXPIRED') {
      paymentTokenRef.current = undefined;
      selectionRef.current = undefined;
      dispatch(progressCleared());
      setRecoveryError('expired');
      return;
    }
    if (checkout.activeTransactionId !== undefined && checkout.activeTransactionId !== null) {
      dispatch(transactionAccepted(checkout.activeTransactionId));
      onStatusRoute();
      return;
    }
    if (
      progress.transactionId === undefined &&
      !submissionUncertain &&
      progress.step !== 'payment' &&
      paymentTokenRef.current === undefined
    ) {
      dispatch(stepChanged('payment'));
    }
  }, [
    checkoutQuery.data,
    dispatch,
    onStatusRoute,
    progress.step,
    progress.transactionId,
    submissionUncertain,
  ]);

  useEffect(() => {
    const current = transactionQuery.data;
    setPollingInterval(
      current === undefined || current.paymentStatus === 'PENDING'
        ? Math.min(Math.max((current?.retryAfterSeconds ?? 2) * 1_000, 1_000), 10_000)
        : 0,
    );
  }, [transactionQuery.data]);

  useEffect(() => {
    const status = readErrorStatus(checkoutQuery.error);
    if (status === 404 || status === 410) {
      dispatch(progressCleared());
      setRecoveryError(status === 410 ? 'expired' : 'missing');
    }
  }, [checkoutQuery.error, dispatch]);

  useEffect(() => {
    const opener = document.querySelector<HTMLElement>('[data-testid="product-checkout-cta"]');
    const background = document.querySelector<HTMLElement>('[data-testid="product-surface"]');
    const previousOverflow = document.body.style.overflow;
    background?.setAttribute('inert', '');
    document.body.style.overflow = 'hidden';
    queueMicrotask(() => dialogRef.current?.querySelector<HTMLElement>('h2')?.focus());
    return () => {
      background?.removeAttribute('inert');
      document.body.style.overflow = previousOverflow;
      opener?.focus();
    };
  }, []);

  useEffect(() => {
    queueMicrotask(() => dialogRef.current?.querySelector<HTMLElement>('h2')?.focus());
  }, [progress.step]);

  const close = (): void => {
    if (submitting) {
      return;
    }
    paymentTokenRef.current = undefined;
    selectionRef.current = undefined;
    dispatch(closeCheckout());
    onClose();
  };

  const trapFocus = (event: KeyboardEvent<HTMLDivElement>): void => {
    if (event.key === 'Escape') {
      event.preventDefault();
      close();
      return;
    }
    if (event.key !== 'Tab') {
      return;
    }
    const focusable = Array.from(
      dialogRef.current?.querySelectorAll<HTMLElement>(focusableSelector) ?? [],
    );
    const first = focusable[0];
    const last = focusable.at(-1);
    if (first === undefined || last === undefined) {
      return;
    }
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  };

  const saveCustomerDelivery = async (
    customer: CustomerRequest,
    delivery: DeliveryRequest,
  ): Promise<void> => {
    const checkout = checkoutQuery.data;
    if (checkout === undefined || progress.checkoutId === undefined) {
      throw new Error('CHECKOUT_NOT_READY');
    }
    const savedCustomer = await replaceCustomer({
      checkoutId: progress.checkoutId,
      version: checkout.version,
      body: customer,
    }).unwrap();
    await replaceDelivery({
      checkoutId: progress.checkoutId,
      version: savedCustomer.version,
      body: delivery,
    }).unwrap();
    await checkoutQuery.refetch();
    dispatch(stepChanged('acceptances'));
  };

  const recoverAfterSubmission = async (): Promise<boolean> => {
    const recovered = await checkoutQuery.refetch();
    const activeTransactionId = recovered.data?.activeTransactionId;
    if (activeTransactionId === undefined || activeTransactionId === null) {
      return false;
    }
    dispatch(transactionAccepted(activeTransactionId));
    onStatusRoute();
    return true;
  };

  const startPayment = async (): Promise<void> => {
    const checkout = checkoutQuery.data;
    const token = paymentTokenRef.current;
    const selection = selectionRef.current;
    if (
      checkout === undefined ||
      progress.checkoutId === undefined ||
      progress.idempotencyKey === undefined ||
      token === undefined ||
      selection === undefined
    ) {
      dispatch(stepChanged('payment'));
      return;
    }
    setSubmitting(true);
    setSubmissionUncertain(false);
    try {
      const accepted = await submitPayment({
        checkoutId: progress.checkoutId,
        version: checkout.version,
        idempotencyKey: progress.idempotencyKey,
        body: {
          quoteId: checkout.quote.quoteId,
          paymentMethodToken: token,
          installments: selection.installments,
          acceptances: {
            termsAcceptanceToken: selection.termsAcceptanceToken,
            personalDataAcceptanceToken: selection.personalDataAcceptanceToken,
          },
        },
      });
      paymentTokenRef.current = undefined;
      selectionRef.current = undefined;
      dispatch(transactionAccepted(accepted.transactionId));
      onStatusRoute();
    } catch (error) {
      paymentTokenRef.current = undefined;
      selectionRef.current = undefined;
      if (error instanceof PaymentCommandError && error.status === 410) {
        dispatch(progressCleared());
        setRecoveryError('expired');
      } else if (
        error instanceof PaymentCommandError &&
        (error.code === 'QUOTE_STALE' || error.code === 'OUT_OF_STOCK')
      ) {
        restartQuote();
      } else if (error instanceof PaymentCommandError && error.status === 412) {
        await checkoutQuery.refetch();
        dispatch(stepChanged('payment'));
      } else if (error instanceof PaymentCommandError && error.status === 422) {
        await configurationQuery.refetch();
        dispatch(stepChanged('payment'));
      } else if (
        error instanceof PaymentCommandError &&
        error.status === 409 &&
        error.code !== 'IDEMPOTENCY_CONFLICT' &&
        error.code !== 'PAYMENT_ALREADY_IN_PROGRESS'
      ) {
        restartQuote();
      } else if (!(await recoverAfterSubmission())) {
        setSubmissionUncertain(true);
        dispatch(stepChanged('status'));
      }
    } finally {
      setSubmitting(false);
    }
  };

  const restartQuote = (): void => {
    paymentTokenRef.current = undefined;
    selectionRef.current = undefined;
    dispatch(progressCleared());
    dispatch(baseApi.util.invalidateTags([{ type: 'Product', id: productId }]));
    onReturn();
  };

  const retryPayment = (): void => {
    paymentTokenRef.current = undefined;
    selectionRef.current = undefined;
    dispatch(returnedToProduct('FAILED'));
    setSubmissionUncertain(false);
    onClose();
  };

  const returnToProduct = (approved: boolean): void => {
    paymentTokenRef.current = undefined;
    selectionRef.current = undefined;
    dispatch(returnedToProduct(approved ? 'APPROVED' : 'FAILED'));
    dispatch(baseApi.util.invalidateTags([{ type: 'Product', id: productId }]));
    onReturn();
  };

  const checkout = checkoutQuery.data;
  const transaction = transactionQuery.data;

  return (
    <div className="checkout-backdrop" role="presentation">
      <div
        className="checkout-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="checkout-step-title"
        aria-describedby="checkout-dialog-description"
        onKeyDown={trapFocus}
        ref={dialogRef}
        data-testid="checkout-dialog"
      >
        <header className="dialog-header">
          <p id="checkout-dialog-description" className="visually-hidden">
            Checkout seguro de cinco pasos.
          </p>
          <ol className="step-indicator" aria-label="Progreso del checkout">
            {['Pago', 'Datos', 'Condiciones', 'Resumen', 'Resultado'].map((label, index) => {
              const current = ['payment', 'customer', 'acceptances', 'review', 'status'].indexOf(
                progress.step,
              );
              return (
                <li
                  key={label}
                  aria-current={index === current ? 'step' : undefined}
                  className={index <= current ? 'active' : undefined}
                >
                  <span>{index + 1}</span>
                  <span className="step-label">{label}</span>
                </li>
              );
            })}
          </ol>
          <button
            className="dialog-close"
            type="button"
            onClick={close}
            disabled={submitting}
            aria-label="Cerrar checkout"
          >
            ×
          </button>
        </header>
        <div className="dialog-body" aria-busy={createState.isLoading || checkoutQuery.isLoading}>
          {recoveryError !== undefined ? (
            <section className="transaction-panel" role="alert" data-testid="checkout-expired">
              <h2 id="checkout-step-title" tabIndex={-1}>
                {recoveryError === 'expired'
                  ? 'La sesión venció'
                  : 'No pudimos recuperar la compra'}
              </h2>
              <p>
                {recoveryError === 'network'
                  ? 'Revisa tu conexión y vuelve al producto para intentarlo.'
                  : 'Vuelve al producto para iniciar un checkout seguro.'}
              </p>
              <button
                className="primary-action"
                type="button"
                onClick={() => returnToProduct(false)}
              >
                Volver al producto
              </button>
            </section>
          ) : checkout === undefined ? (
            <section className="transaction-panel" role="status" aria-live="polite">
              <h2 id="checkout-step-title" tabIndex={-1}>
                Preparando checkout
              </h2>
              <p>Consultando producto, stock y cotización…</p>
            </section>
          ) : progress.step === 'payment' ? (
            configurationQuery.isLoading ? (
              <section className="transaction-panel" role="status" aria-live="polite">
                <h2 id="checkout-step-title" tabIndex={-1}>
                  Preparando método de pago
                </h2>
                <p>Cargando la configuración segura…</p>
              </section>
            ) : paymentAdapter === undefined || configurationQuery.isError ? (
              <section className="transaction-panel" role="alert">
                <h2 id="checkout-step-title" tabIndex={-1}>
                  Método de pago no disponible
                </h2>
                <p>No se enviará ningún dato. Reintenta la configuración.</p>
                <button
                  className="primary-action"
                  type="button"
                  onClick={() => void configurationQuery.refetch()}
                >
                  Reintentar
                </button>
              </section>
            ) : (
              <CardStep
                adapter={paymentAdapter}
                onTokenized={(token) => {
                  paymentTokenRef.current = token;
                  dispatch(stepChanged('customer'));
                }}
              />
            )
          ) : progress.step === 'customer' ? (
            <CustomerDeliveryStep
              checkout={checkout}
              onBack={() => {
                paymentTokenRef.current = undefined;
                dispatch(stepChanged('payment'));
              }}
              onSave={saveCustomerDelivery}
            />
          ) : progress.step === 'acceptances' && configurationQuery.data !== undefined ? (
            <AcceptancesStep
              configuration={configurationQuery.data}
              onBack={() => dispatch(stepChanged('customer'))}
              onContinue={(selection) => {
                selectionRef.current = selection;
                dispatch(stepChanged('review'));
              }}
            />
          ) : progress.step === 'review' && selectionRef.current !== undefined ? (
            <ReviewStep
              checkout={checkout}
              installments={selectionRef.current.installments}
              submitting={submitting}
              onBack={() => {
                selectionRef.current = undefined;
                dispatch(stepChanged('acceptances'));
              }}
              onRefreshQuote={restartQuote}
              onSubmit={() => void startPayment()}
            />
          ) : submissionUncertain && progress.transactionId === undefined ? (
            <section
              className="transaction-panel transaction-unknown"
              role="status"
              aria-live="polite"
              data-testid="transaction-unknown"
            >
              <p className="eyebrow">Paso 5 de 5</p>
              <h2 id="checkout-step-title" tabIndex={-1}>
                Seguimos verificando
              </h2>
              <p>No pudimos confirmar la recepción. No repitas el pago; consulta la sesión.</p>
              <button
                className="primary-action"
                type="button"
                onClick={() => void recoverAfterSubmission()}
              >
                Consultar sesión
              </button>
            </section>
          ) : (
            <TransactionStep
              transaction={transaction}
              loading={transactionQuery.isFetching && pollingInterval > 0}
              error={transactionQuery.isError}
              onRefresh={() => void transactionQuery.refetch()}
              onReturn={returnToProduct}
              onRetry={retryPayment}
            />
          )}
        </div>
      </div>
    </div>
  );
};
