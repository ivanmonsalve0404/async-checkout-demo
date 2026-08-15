import { useRef, useState, type FormEvent } from 'react';
import type { CustomerRequest, DeliveryRequest, CheckoutResponse } from '../api/checkout-api';

export interface CustomerDeliveryStepProps {
  readonly checkout: CheckoutResponse;
  readonly onBack: () => void;
  readonly onSave: (customer: CustomerRequest, delivery: DeliveryRequest) => Promise<void>;
}

interface FormErrors {
  readonly fullName?: string;
  readonly email?: string;
  readonly phone?: string;
  readonly addressLine1?: string;
  readonly city?: string;
  readonly region?: string;
  readonly postalCode?: string;
}

const normalizedText = (value: FormDataEntryValue | null): string =>
  String(value ?? '')
    .trim()
    .replace(/\s+/g, ' ');

export const readCustomerDelivery = (
  form: HTMLFormElement,
): { readonly customer: CustomerRequest; readonly delivery: DeliveryRequest } => {
  const data = new FormData(form);
  const addressLine2 = normalizedText(data.get('addressLine2'));
  const postalCode = normalizedText(data.get('postalCode'));
  const deliveryInstructions = normalizedText(data.get('deliveryInstructions'));
  return {
    customer: {
      fullName: normalizedText(data.get('fullName')),
      email: normalizedText(data.get('email')).toLowerCase(),
      phone: normalizedText(data.get('phone')).replace(/[ ()-]/g, ''),
    },
    delivery: {
      addressLine1: normalizedText(data.get('addressLine1')),
      city: normalizedText(data.get('city')),
      region: normalizedText(data.get('region')),
      ...(addressLine2 === '' ? {} : { addressLine2 }),
      ...(postalCode === '' ? {} : { postalCode }),
      ...(deliveryInstructions === '' ? {} : { deliveryInstructions }),
    },
  };
};

export const validateCustomerDelivery = (
  customer: CustomerRequest,
  delivery: DeliveryRequest,
): FormErrors => {
  const errors: {
    fullName?: string;
    email?: string;
    phone?: string;
    addressLine1?: string;
    city?: string;
    region?: string;
    postalCode?: string;
  } = {};
  const humanName = /^[\p{L}\p{M} .'-]+$/u;
  if (
    customer.fullName.length < 2 ||
    customer.fullName.length > 120 ||
    !humanName.test(customer.fullName)
  ) {
    errors.fullName = 'Ingresa un nombre completo válido.';
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(customer.email) || customer.email.length > 254) {
    errors.email = 'Ingresa un correo electrónico válido.';
  }
  if (!/^\+?[0-9]{8,15}$/.test(customer.phone)) {
    errors.phone = 'Ingresa entre 8 y 15 dígitos, con prefijo de país opcional.';
  }
  if (
    delivery.addressLine1.length < 5 ||
    delivery.addressLine1.length > 160 ||
    /[<>]/.test(delivery.addressLine1)
  ) {
    errors.addressLine1 = 'Ingresa una dirección válida de máximo 160 caracteres.';
  }
  if (delivery.city.length < 2 || delivery.city.length > 80 || !humanName.test(delivery.city)) {
    errors.city = 'Ingresa una ciudad válida.';
  }
  if (
    delivery.region.length < 2 ||
    delivery.region.length > 80 ||
    !humanName.test(delivery.region)
  ) {
    errors.region = 'Ingresa un departamento o región válido.';
  }
  if (delivery.postalCode !== undefined && !/^[A-Za-z0-9 -]{3,12}$/.test(delivery.postalCode)) {
    errors.postalCode = 'Usa entre 3 y 12 letras, números, espacios o guiones.';
  }
  return errors;
};

export const CustomerDeliveryStep = ({ checkout, onBack, onSave }: CustomerDeliveryStepProps) => {
  const [errors, setErrors] = useState<FormErrors>({});
  const [saving, setSaving] = useState(false);
  const [networkError, setNetworkError] = useState(false);
  const summaryRef = useRef<HTMLDivElement>(null);

  const submit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    const values = readCustomerDelivery(event.currentTarget);
    const nextErrors = validateCustomerDelivery(values.customer, values.delivery);
    setErrors(nextErrors);
    if (Object.values(nextErrors).some(Boolean)) {
      queueMicrotask(() => summaryRef.current?.focus());
      return;
    }
    setSaving(true);
    setNetworkError(false);
    try {
      await onSave(values.customer, values.delivery);
    } catch {
      setNetworkError(true);
      queueMicrotask(() => summaryRef.current?.focus());
    } finally {
      setSaving(false);
    }
  };

  const currentCustomer = checkout.customer;
  const currentDelivery = checkout.deliveryDetails;
  return (
    <form onSubmit={(event) => void submit(event)} noValidate data-testid="checkout-step-customer">
      <header className="step-heading">
        <p className="eyebrow">Paso 2 de 5</p>
        <h2 id="checkout-step-title" tabIndex={-1}>
          Tus datos y entrega
        </h2>
        <p>Usaremos estos datos únicamente para gestionar esta compra.</p>
      </header>
      {(Object.values(errors).some(Boolean) || networkError) && (
        <div className="error-summary" role="alert" tabIndex={-1} ref={summaryRef}>
          <strong>No pudimos continuar</strong>
          <p>
            {networkError
              ? 'Conservamos el formulario. Reintenta cuando tengas conexión.'
              : 'Corrige los campos indicados.'}
          </p>
        </div>
      )}
      <fieldset className="form-grid">
        <legend>Contacto</legend>
        <label className="field field-wide">
          <span>Nombre completo</span>
          <input
            name="fullName"
            autoComplete="name"
            maxLength={120}
            defaultValue={currentCustomer?.fullName ?? ''}
            aria-invalid={errors.fullName === undefined ? undefined : true}
          />
          {errors.fullName !== undefined && (
            <small className="field-error">{errors.fullName}</small>
          )}
        </label>
        <label className="field">
          <span>Correo electrónico</span>
          <input
            name="email"
            type="email"
            autoComplete="email"
            maxLength={254}
            defaultValue={currentCustomer?.email ?? ''}
            aria-invalid={errors.email === undefined ? undefined : true}
          />
          {errors.email !== undefined && <small className="field-error">{errors.email}</small>}
        </label>
        <label className="field">
          <span>Teléfono</span>
          <input
            name="phone"
            type="tel"
            autoComplete="tel"
            maxLength={16}
            defaultValue={currentCustomer?.phone ?? ''}
            aria-invalid={errors.phone === undefined ? undefined : true}
          />
          {errors.phone !== undefined && <small className="field-error">{errors.phone}</small>}
        </label>
      </fieldset>
      <fieldset className="form-grid">
        <legend>Entrega</legend>
        <label className="field field-wide">
          <span>Dirección</span>
          <input
            name="addressLine1"
            autoComplete="address-line1"
            maxLength={160}
            defaultValue={currentDelivery?.addressLine1 ?? ''}
            aria-invalid={errors.addressLine1 === undefined ? undefined : true}
          />
          {errors.addressLine1 !== undefined && (
            <small className="field-error">{errors.addressLine1}</small>
          )}
        </label>
        <label className="field field-wide">
          <span>Complemento (opcional)</span>
          <input
            name="addressLine2"
            autoComplete="address-line2"
            maxLength={160}
            defaultValue={currentDelivery?.addressLine2 ?? ''}
          />
        </label>
        <label className="field">
          <span>Ciudad</span>
          <input
            name="city"
            autoComplete="address-level2"
            maxLength={80}
            defaultValue={currentDelivery?.city ?? ''}
            aria-invalid={errors.city === undefined ? undefined : true}
          />
          {errors.city !== undefined && <small className="field-error">{errors.city}</small>}
        </label>
        <label className="field">
          <span>Departamento o región</span>
          <input
            name="region"
            autoComplete="address-level1"
            maxLength={80}
            defaultValue={currentDelivery?.region ?? ''}
            aria-invalid={errors.region === undefined ? undefined : true}
          />
          {errors.region !== undefined && <small className="field-error">{errors.region}</small>}
        </label>
        <label className="field">
          <span>Código postal (opcional)</span>
          <input
            name="postalCode"
            autoComplete="postal-code"
            maxLength={12}
            defaultValue={currentDelivery?.postalCode ?? ''}
            aria-invalid={errors.postalCode === undefined ? undefined : true}
          />
          {errors.postalCode !== undefined && (
            <small className="field-error">{errors.postalCode}</small>
          )}
        </label>
        <label className="field field-wide">
          <span>Instrucciones de entrega (opcional)</span>
          <textarea
            name="deliveryInstructions"
            maxLength={250}
            defaultValue={currentDelivery?.deliveryInstructions ?? ''}
          />
        </label>
      </fieldset>
      <div className="dialog-actions">
        <button className="quiet-action" type="button" onClick={onBack} disabled={saving}>
          Atrás
        </button>
        <button
          className="primary-action"
          type="submit"
          disabled={saving}
          aria-busy={saving}
          data-testid="customer-delivery-save"
        >
          {saving ? 'Guardando…' : 'Continuar'}
        </button>
      </div>
    </form>
  );
};
