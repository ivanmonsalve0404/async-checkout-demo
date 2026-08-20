import type { Result } from '../result/result';

export interface ProviderPaymentCommand {
  readonly reference: string;
  readonly amountInCents: number;
  readonly customerEmail: string;
  readonly currency: 'COP';
  readonly installments: number;
  readonly paymentMethodHandle: Readonly<{ kind: 'OPAQUE_TOKEN'; value: string }>;
  readonly acceptances: Readonly<{
    termsAcceptanceToken: string;
    personalDataAcceptanceToken: string;
  }>;
}

export type ProviderCreateOutcome =
  | Readonly<{
      kind: 'ACKNOWLEDGED';
      providerId: string;
      status: Exclude<ProviderStatus, 'UNKNOWN_EXTERNAL'>;
      reference: string;
      amountInCents: number;
      currency: string;
    }>
  | Readonly<{ kind: 'DEFINITIVE_REJECTION' }>
  | Readonly<{ kind: 'PROVEN_NOT_SENT' }>
  | Readonly<{ kind: 'OUTCOME_UNKNOWN' }>
  | Readonly<{ kind: 'PROTOCOL_VIOLATION_AFTER_POSSIBLE_SEND' }>;

export type ProviderStatus =
  'PENDING' | 'APPROVED' | 'DECLINED' | 'VOIDED' | 'ERROR' | 'UNKNOWN_EXTERNAL';
export interface ProviderObservation {
  readonly providerId: string;
  readonly reference: string;
  readonly amountInCents: number;
  readonly currency: string;
  readonly status: ProviderStatus;
}

export type ProviderError = Readonly<{
  code:
    | 'FAKE_SCRIPT_EXHAUSTED'
    | 'EVENT_REJECTED'
    | 'ENVIRONMENT_DISABLED'
    | 'PROVIDER_UNAVAILABLE'
    | 'PROVIDER_TIMEOUT'
    | 'PROVIDER_RATE_LIMITED'
    | 'PROVIDER_PROTOCOL_ERROR'
    | 'REFERENCE_LOOKUP_UNSUPPORTED';
}>;

export interface PaymentProvider {
  getPublicConfiguration(): Result<
    Readonly<{
      mode: 'fake' | 'sandbox';
      captureVariant: 'FAKE_CONTRACT' | 'DIRECT_JWE' | 'HOSTED_COMPONENT';
      publicKey: string;
      installments: readonly number[];
      authorizedUntilUtc?: string;
    }>,
    ProviderError
  >;
  createOnce(
    command: ProviderPaymentCommand,
  ): Promise<Result<ProviderCreateOutcome, ProviderError>>;
  getByReference(reference: string): Promise<Result<ProviderObservation, ProviderError>>;
  getById(
    providerId: string,
    expectedReference?: string,
  ): Promise<Result<ProviderObservation, ProviderError>>;
  verifyAndNormalizeEvent(
    eventName: string,
  ): Result<Readonly<{ eventName: string }>, ProviderError>;
}

export const PAYMENT_PROVIDER = Symbol('PAYMENT_PROVIDER');
