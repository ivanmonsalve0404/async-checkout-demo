import type { Result } from '../result/result';

export interface ProviderPaymentCommand {
  readonly reference: string;
  readonly amountInCents: number;
  readonly currency: 'COP';
  readonly installments: number;
  readonly paymentMethodHandle: Readonly<{ kind: 'SYNTHETIC_FAKE' }>;
}

export type ProviderCreateOutcome =
  | Readonly<{
      kind: 'ACKNOWLEDGED';
      providerId: string;
      status: 'PENDING' | 'APPROVED' | 'DECLINED';
    }>
  | Readonly<{ kind: 'DEFINITIVE_REJECTION' }>
  | Readonly<{ kind: 'PROVEN_NOT_SENT' }>
  | Readonly<{ kind: 'OUTCOME_UNKNOWN' }>
  | Readonly<{ kind: 'PROTOCOL_VIOLATION_AFTER_POSSIBLE_SEND' }>;

export type ProviderStatus =
  'PENDING' | 'APPROVED' | 'DECLINED' | 'VOIDED' | 'ERROR' | 'UNKNOWN_EXTERNAL';
export type ProviderError = Readonly<{ code: 'FAKE_SCRIPT_EXHAUSTED' | 'EVENT_REJECTED' }>;

export interface PaymentProvider {
  getPublicConfiguration(): Result<
    Readonly<{ mode: 'fake'; installments: readonly number[] }>,
    ProviderError
  >;
  createOnce(
    command: ProviderPaymentCommand,
  ): Promise<Result<ProviderCreateOutcome, ProviderError>>;
  getById(providerId: string): Promise<Result<ProviderStatus, ProviderError>>;
  verifyAndNormalizeEvent(
    eventName: string,
  ): Result<Readonly<{ eventName: string }>, ProviderError>;
}
