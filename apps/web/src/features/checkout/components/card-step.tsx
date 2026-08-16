import { useEffect, useRef, useState, type FormEvent } from 'react';
import type { PaymentTokenizationAdapter } from '../services/payment-tokenization';
import {
  digitsOnly,
  hasCardErrors,
  validateCard,
  type CardInput,
  type CardValidationErrors,
} from '../validation/card-validation';

export interface CardStepProps {
  readonly adapter: PaymentTokenizationAdapter;
  readonly expired?: boolean;
  readonly onTokenized: (token: string) => void;
}

const emptyCard: CardInput = {
  number: '',
  expiry: '',
  securityCode: '',
  holderName: '',
};

const formatNumber = (value: string): string =>
  digitsOnly(value)
    .slice(0, 16)
    .replace(/(.{4})/g, '$1 ')
    .trim();

const formatExpiry = (value: string): string => {
  const digits = digitsOnly(value).slice(0, 4);
  return digits.length > 2 ? digits.slice(0, 2) + '/' + digits.slice(2) : digits;
};
export const cardInputTtlMs = 5 * 60 * 1_000;

export const CardStep = ({ adapter, expired = false, onTokenized }: CardStepProps) => {
  const [card, setCard] = useState<CardInput>(emptyCard);
  const [errors, setErrors] = useState<CardValidationErrors>({});
  const [submitting, setSubmitting] = useState(false);
  const [tokenizationError, setTokenizationError] = useState<string>();
  const [captureExpired, setCaptureExpired] = useState(false);
  const summaryRef = useRef<HTMLDivElement>(null);
  const mountedRef = useRef(true);
  const captureTimerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(
    () => () => {
      mountedRef.current = false;
      if (captureTimerRef.current !== undefined) {
        globalThis.clearTimeout(captureTimerRef.current);
      }
    },
    [],
  );

  const hasCardData =
    card.number.length > 0 ||
    card.expiry.length > 0 ||
    card.securityCode.length > 0 ||
    card.holderName.length > 0;
  useEffect(() => {
    if (!hasCardData) {
      if (captureTimerRef.current !== undefined) {
        globalThis.clearTimeout(captureTimerRef.current);
        captureTimerRef.current = undefined;
      }
      return;
    }
    captureTimerRef.current ??= globalThis.setTimeout(() => {
      captureTimerRef.current = undefined;
      if (!mountedRef.current) return;
      setCard(emptyCard);
      setErrors({});
      setTokenizationError(undefined);
      setCaptureExpired(true);
      queueMicrotask(() => summaryRef.current?.focus());
    }, cardInputTtlMs);
  }, [hasCardData]);
  const update = (field: keyof CardInput, value: string): void => {
    setCard((current) => ({ ...current, [field]: value }));
    setErrors((current) => ({ ...current, [field]: undefined }));
    setTokenizationError(undefined);
    setCaptureExpired(false);
  };

  const submit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    const validation = validateCard(card);
    setErrors(validation.errors);
    if (hasCardErrors(validation.errors)) {
      queueMicrotask(() => summaryRef.current?.focus());
      return;
    }
    setCard(emptyCard);
    setSubmitting(true);
    setTokenizationError(undefined);
    try {
      const token = await adapter.tokenize(card);
      if (!mountedRef.current) {
        return;
      }
      onTokenized(token);
    } catch {
      if (!mountedRef.current) {
        return;
      }
      setTokenizationError(
        adapter.mode === 'SANDBOX_READY_DISABLED'
          ? 'La captura sandbox sigue deshabilitada. Usa el proveedor falso local.'
          : 'No pudimos preparar el método de pago. Vuelve a ingresarlo.',
      );
      queueMicrotask(() => summaryRef.current?.focus());
    } finally {
      if (mountedRef.current) {
        setSubmitting(false);
      }
    }
  };
  const methodExpired = expired || captureExpired;

  return (
    <form onSubmit={(event) => void submit(event)} noValidate data-testid="checkout-step-payment">
      <header className="step-heading">
        <p className="eyebrow">Paso 1 de 5</p>
        <h2 id="checkout-step-title" tabIndex={-1}>
          Método de pago
        </h2>
        <p>Los datos se usan sólo para crear un token efímero y esta aplicación no los guarda.</p>
      </header>

      {(hasCardErrors(errors) || tokenizationError !== undefined || methodExpired) && (
        <div className="error-summary" role="alert" tabIndex={-1} ref={summaryRef}>
          <strong>Revisa el método de pago</strong>
          <p>
            {tokenizationError ??
              (methodExpired
                ? 'El método de pago venció. Vuelve a ingresar todos los datos para continuar.'
                : 'Corrige los campos indicados para continuar.')}
          </p>
        </div>
      )}

      <div className="form-grid payment-boundary" aria-label="Superficie segura de pago">
        <label className="field field-wide">
          <span>Número de tarjeta</span>
          <input
            name="payment-number"
            inputMode="numeric"
            autoComplete="cc-number"
            value={card.number}
            maxLength={19}
            aria-invalid={errors.number === undefined ? undefined : true}
            aria-describedby={
              errors.number === undefined ? 'payment-number-help' : 'payment-number-error'
            }
            onChange={(event) => update('number', formatNumber(event.target.value))}
          />
          <small id="payment-number-help">Visa o Mastercard, 16 dígitos.</small>
          {errors.number !== undefined && (
            <small id="payment-number-error" className="field-error">
              {errors.number}
            </small>
          )}
        </label>
        <label className="field">
          <span>Vencimiento</span>
          <input
            name="payment-expiry"
            inputMode="numeric"
            autoComplete="cc-exp"
            placeholder="MM/AA"
            value={card.expiry}
            maxLength={5}
            aria-invalid={errors.expiry === undefined ? undefined : true}
            aria-describedby={errors.expiry === undefined ? undefined : 'payment-expiry-error'}
            onChange={(event) => update('expiry', formatExpiry(event.target.value))}
          />
          {errors.expiry !== undefined && (
            <small id="payment-expiry-error" className="field-error">
              {errors.expiry}
            </small>
          )}
        </label>
        <label className="field">
          <span>Código de seguridad</span>
          <input
            name="payment-security-code"
            inputMode="numeric"
            autoComplete="cc-csc"
            value={card.securityCode}
            maxLength={3}
            aria-invalid={errors.securityCode === undefined ? undefined : true}
            aria-describedby={errors.securityCode === undefined ? undefined : 'payment-code-error'}
            onChange={(event) => update('securityCode', digitsOnly(event.target.value).slice(0, 3))}
          />
          {errors.securityCode !== undefined && (
            <small id="payment-code-error" className="field-error">
              {errors.securityCode}
            </small>
          )}
        </label>
        <label className="field field-wide">
          <span>Nombre en la tarjeta</span>
          <input
            name="payment-holder"
            autoComplete="cc-name"
            value={card.holderName}
            maxLength={120}
            aria-invalid={errors.holderName === undefined ? undefined : true}
            aria-describedby={errors.holderName === undefined ? undefined : 'payment-holder-error'}
            onChange={(event) => update('holderName', event.target.value)}
          />
          {errors.holderName !== undefined && (
            <small id="payment-holder-error" className="field-error">
              {errors.holderName}
            </small>
          )}
        </label>
      </div>
      <button
        className="primary-action"
        type="submit"
        disabled={submitting}
        aria-busy={submitting}
        data-testid="payment-tokenize"
      >
        {submitting ? 'Protegiendo método…' : 'Continuar'}
      </button>
    </form>
  );
};
