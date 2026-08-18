import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react';
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
  type CheckoutResponse,
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
import { saveWithCanonicalRecovery } from '../services/save-with-canonical-recovery';
import { useEphemeralPaymentToken } from '../services/use-ephemeral-payment-token';
import { useTransactionPolling } from '../services/use-transaction-polling';
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

const customerMatches = (checkout: CheckoutResponse, expected: CustomerRequest): boolean =>
  checkout.customer?.fullName === expected.fullName &&
  checkout.customer.email === expected.email &&
  checkout.customer.phone === expected.phone;

const deliveryMatches = (checkout: CheckoutResponse, expected: DeliveryRequest): boolean =>
  checkout.deliveryDetails?.addressLine1 === expected.addressLine1 &&
  checkout.deliveryDetails.city === expected.city &&
  checkout.deliveryDetails.region === expected.region &&
  checkout.deliveryDetails.addressLine2 === expected.addressLine2 &&
  checkout.deliveryDetails.postalCode === expected.postalCode &&
  checkout.deliveryDetails.deliveryInstructions === expected.deliveryInstructions;

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
  const transactionQuery = useGetTransactionQuery(progress.transactionId ?? '', {
    skip: progress.transactionId === undefined,
    pollingInterval: 0,
    refetchOnFocus: true,
    refetchOnReconnect: true,
    refetchOnMountOrArgChange: true,
  });
  const { automaticPollingStopped } = useTransactionPolling(
    progress.transactionId,
    transactionQuery.data,
    transactionQuery.refetch,
  );
  const dialogRef = useRef<HTMLDivElement>(null);
  const startedRef = useRef(false);
  const submittingRef = useRef(false);
  const selectionRef = useRef<PaymentSelection | undefined>(undefined);
  const [submitting, setSubmitting] = useState(false);
  const [recoveryError, setRecoveryError] = useState<'missing' | 'expired' | 'network'>();
  const [submissionUncertain, setSubmissionUncertain] = useState(false);
  const [paymentExpired, setPaymentExpired] = useState(false);
  const expirePayment = useCallback((): void => {
    selectionRef.current = undefined;
    setPaymentExpired(true);
    dispatch(stepChanged('payment'));
  }, [dispatch]);
  const {
    clear: clearPaymentToken,
    get: getPaymentToken,
    set: setPaymentToken,
  } = useEphemeralPaymentToken(expirePayment);
  const clearPaymentSecrets = useCallback((): void => {
    clearPaymentToken();
    selectionRef.current = undefined;
  }, [clearPaymentToken]);

  const paymentAdapter = useMemo(
    () =>
      configurationQuery.data === undefined
        ? undefined
        : selectTokenizationAdapter(
            configurationQuery.data.captureVariant,
            configurationQuery.data.sandboxPublicKey,
            configurationQuery.data.expiresAt,
          ),
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
      clearPaymentSecrets();
      dispatch(progressCleared());
      setRecoveryError('expired');
      return;
    }
    if (checkout.activeTransactionId !== undefined && checkout.activeTransactionId !== null) {
      if (progress.transactionId !== checkout.activeTransactionId) {
        dispatch(transactionAccepted(checkout.activeTransactionId));
      }
      if (mode !== 'status') {
        onStatusRoute();
      }
      return;
    }
    if (
      progress.transactionId === undefined &&
      !submissionUncertain &&
      progress.step !== 'payment' &&
      getPaymentToken() === undefined
    ) {
      dispatch(stepChanged('payment'));
    }
  }, [
    checkoutQuery.data,
    clearPaymentSecrets,
    dispatch,
    getPaymentToken,
    mode,
    onStatusRoute,
    progress.step,
    progress.transactionId,
    submissionUncertain,
  ]);

  useEffect(() => {
    const status = readErrorStatus(checkoutQuery.error);
    if (status === 404 || status === 410) {
      dispatch(progressCleared());
      setRecoveryError(status === 410 ? 'expired' : 'missing');
    }
  }, [checkoutQuery.error, dispatch]);

  useEffect(() => {
    const background = document.querySelector<HTMLElement>('[data-testid="product-surface"]');
    const previousOverflow = document.body.style.overflow;
    background?.setAttribute('inert', '');
    document.body.style.overflow = 'hidden';
    queueMicrotask(() => dialogRef.current?.querySelector<HTMLElement>('h2')?.focus());
    return () => {
      background?.removeAttribute('inert');
      document.body.style.overflow = previousOverflow;
      queueMicrotask(() =>
        document.querySelector<HTMLElement>('[data-testid="product-checkout-cta"]')?.focus(),
      );
    };
  }, []);

  const focusSurface =
    recoveryError !== undefined
      ? `recovery:${recoveryError}`
      : checkoutQuery.data === undefined
        ? 'checkout-loading'
        : progress.step === 'payment' && configurationQuery.isLoading
          ? 'payment-loading'
          : progress.step;
  useEffect(() => {
    queueMicrotask(() => dialogRef.current?.querySelector<HTMLElement>('h2')?.focus());
  }, [focusSurface]);

  const close = (): void => {
    if (submittingRef.current) {
      return;
    }
    clearPaymentSecrets();
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
    const checkoutId = progress.checkoutId;
    if (checkout === undefined || checkoutId === undefined) {
      throw new Error('CHECKOUT_NOT_READY');
    }
    const customerVersion = await saveWithCanonicalRecovery<CheckoutResponse>(
      checkout.version,
      (version) =>
        replaceCustomer({
          checkoutId,
          version,
          body: customer,
        }).unwrap(),
      () => checkoutQuery.refetch(),
      (canonical) => customerMatches(canonical, customer),
    );
    await saveWithCanonicalRecovery<CheckoutResponse>(
      customerVersion,
      (version) =>
        replaceDelivery({
          checkoutId,
          version,
          body: delivery,
        }).unwrap(),
      () => checkoutQuery.refetch(),
      (canonical) => deliveryMatches(canonical, delivery),
    );
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
    if (submittingRef.current) {
      return;
    }
    const checkout = checkoutQuery.data;
    const token = getPaymentToken();
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
    submittingRef.current = true;
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
      clearPaymentSecrets();
      dispatch(transactionAccepted(accepted.transactionId));
      onStatusRoute();
    } catch (error) {
      clearPaymentSecrets();
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
      } else if (!(await recoverAfterSubmission())) {
        setSubmissionUncertain(true);
        dispatch(stepChanged('status'));
      }
    } finally {
      submittingRef.current = false;
      setSubmitting(false);
    }
  };

  const restartQuote = (): void => {
    clearPaymentSecrets();
    dispatch(progressCleared());
    dispatch(baseApi.util.invalidateTags([{ type: 'Product', id: productId }]));
    onReturn();
  };

  const retryPayment = (): void => {
    clearPaymentSecrets();
    dispatch(returnedToProduct('FAILED'));
    setSubmissionUncertain(false);
    onClose();
  };

  const returnToProduct = (approved: boolean): void => {
    clearPaymentSecrets();
    dispatch(
      transactionQuery.data?.paymentStatus !== 'PENDING' &&
        transactionQuery.data?.integrityStatus === 'OK'
        ? returnedToProduct(approved ? 'APPROVED' : 'FAILED')
        : closeCheckout(),
    );
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
                expired={paymentExpired}
                onTokenized={(token) => {
                  setPaymentToken(token);
                  setPaymentExpired(false);
                  dispatch(stepChanged('customer'));
                }}
              />
            )
          ) : progress.step === 'customer' ? (
            <CustomerDeliveryStep
              checkout={checkout}
              onBack={() => {
                clearPaymentSecrets();
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
              loading={transactionQuery.isFetching}
              automaticPollingStopped={automaticPollingStopped}
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
