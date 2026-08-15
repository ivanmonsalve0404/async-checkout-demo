import { useRef, useState, type FormEvent } from 'react';
import type { PaymentConfigurationResponse } from '../api/checkout-api';

export interface PaymentSelection {
  readonly installments: number;
  readonly termsAcceptanceToken: string;
  readonly personalDataAcceptanceToken: string;
}

export interface AcceptancesStepProps {
  readonly configuration: PaymentConfigurationResponse;
  readonly onBack: () => void;
  readonly onContinue: (selection: PaymentSelection) => void;
}

export const AcceptancesStep = ({ configuration, onBack, onContinue }: AcceptancesStepProps) => {
  const [termsAccepted, setTermsAccepted] = useState(false);
  const [personalDataAccepted, setPersonalDataAccepted] = useState(false);
  const [installments, setInstallments] = useState(configuration.allowedInstallments[0] ?? 1);
  const [invalid, setInvalid] = useState(false);
  const summaryRef = useRef<HTMLDivElement>(null);
  const terms = configuration.acceptanceContracts.find(({ type }) => type === 'TERMS');
  const personalData = configuration.acceptanceContracts.find(
    ({ type }) => type === 'PERSONAL_DATA',
  );

  const submit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    if (
      !termsAccepted ||
      !personalDataAccepted ||
      terms === undefined ||
      personalData === undefined
    ) {
      setInvalid(true);
      queueMicrotask(() => summaryRef.current?.focus());
      return;
    }
    onContinue({
      installments,
      termsAcceptanceToken: terms.acceptanceToken,
      personalDataAcceptanceToken: personalData.acceptanceToken,
    });
  };

  return (
    <form onSubmit={submit} noValidate data-testid="checkout-step-acceptances">
      <header className="step-heading">
        <p className="eyebrow">Paso 3 de 5</p>
        <h2 id="checkout-step-title" tabIndex={-1}>
          Condiciones y cuotas
        </h2>
        <p>Revisa y acepta cada documento por separado.</p>
      </header>
      {invalid && (
        <div className="error-summary" role="alert" tabIndex={-1} ref={summaryRef}>
          <strong>Faltan confirmaciones</strong>
          <p>Acepta las dos condiciones para continuar.</p>
        </div>
      )}
      <label className="field">
        <span>Número de cuotas</span>
        <select
          value={installments}
          onChange={(event) => setInstallments(Number(event.target.value))}
        >
          {configuration.allowedInstallments.map((value) => (
            <option key={value} value={value}>
              {value === 1 ? '1 cuota' : String(value) + ' cuotas'}
            </option>
          ))}
        </select>
      </label>
      <div className="acceptance-list">
        {terms !== undefined && (
          <label className="acceptance-control">
            <input
              type="checkbox"
              checked={termsAccepted}
              onChange={(event) => {
                setTermsAccepted(event.target.checked);
                setInvalid(false);
              }}
            />
            <span>
              Acepto los{' '}
              <a href={terms.permalink} target="_blank" rel="noopener noreferrer">
                términos y condiciones
              </a>
              .
            </span>
          </label>
        )}
        {personalData !== undefined && (
          <label className="acceptance-control">
            <input
              type="checkbox"
              checked={personalDataAccepted}
              onChange={(event) => {
                setPersonalDataAccepted(event.target.checked);
                setInvalid(false);
              }}
            />
            <span>
              Autorizo el{' '}
              <a href={personalData.permalink} target="_blank" rel="noopener noreferrer">
                tratamiento de mis datos personales
              </a>
              .
            </span>
          </label>
        )}
      </div>
      <div className="dialog-actions">
        <button className="quiet-action" type="button" onClick={onBack}>
          Atrás
        </button>
        <button className="primary-action" type="submit" data-testid="acceptances-continue">
          Revisar compra
        </button>
      </div>
    </form>
  );
};
