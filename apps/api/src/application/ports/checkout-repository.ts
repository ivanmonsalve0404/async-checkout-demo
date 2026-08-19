import type { Result } from '../result/result';
import type {
  Checkout,
  Customer,
  Delivery,
  DeliveryDetails,
  PaymentStatus,
  PaymentSubmission,
  ProviderStatus,
  Transaction,
} from '../../domain/checkout/checkout';

export type CheckoutRepositoryError = Readonly<{
  code:
    | 'CHECKOUT_NOT_FOUND'
    | 'VERSION_MISMATCH'
    | 'IDEMPOTENCY_CONFLICT'
    | 'PAYMENT_ALREADY_IN_PROGRESS'
    | 'OUT_OF_STOCK'
    | 'FINAL_STATE_CONFLICT'
    | 'APPROVED_INVENTORY_CONFLICT'
    | 'REPOSITORY_UNAVAILABLE';
}>;

export interface PreparedPayment {
  readonly kind: 'CREATED' | 'REPLAY';
  readonly checkout: Checkout;
  readonly transaction: Transaction;
  readonly submission: PaymentSubmission;
}
export interface ReconciliationCheck {
  readonly attempts: number;
  readonly lastCheckedAt: string;
  readonly nextCheckAt: string;
}

export interface CheckoutRepository {
  create(checkout: Checkout): Promise<Result<Checkout, CheckoutRepositoryError>>;
  findCheckout(checkoutId: string): Promise<Result<Checkout | null, CheckoutRepositoryError>>;
  replaceCustomer(
    checkoutId: string,
    capabilityHash: string,
    expectedVersion: number,
    customer: Omit<Customer, 'version'>,
  ): Promise<Result<Checkout, CheckoutRepositoryError>>;
  replaceDeliveryDetails(
    checkoutId: string,
    capabilityHash: string,
    expectedVersion: number,
    details: Omit<DeliveryDetails, 'version'>,
  ): Promise<Result<Checkout, CheckoutRepositoryError>>;
  findIdempotency(
    input: Readonly<{
      checkoutId: string;
      keyHash: string;
      semanticHash: string;
    }>,
  ): Promise<Result<PreparedPayment | null, CheckoutRepositoryError>>;
  preparePayment(
    input: Readonly<{
      checkoutId: string;
      capabilityHash: string;
      expectedVersion: number;
      keyHash: string;
      semanticHash: string;
      transaction: Transaction;
      submission: PaymentSubmission;
    }>,
  ): Promise<Result<PreparedPayment, CheckoutRepositoryError>>;
  claimDispatch(
    transactionId: string,
    updatedAt: string,
    leaseUntil: string,
  ): Promise<
    Result<
      Readonly<{ kind: 'CLAIMED' | 'NOT_LEADER'; transaction: Transaction }>,
      CheckoutRepositoryError
    >
  >;
  acknowledgeProvider(
    transactionId: string,
    providerId: string,
    providerStatus: Exclude<ProviderStatus, null>,
    updatedAt: string,
    check: ReconciliationCheck,
  ): Promise<Result<Transaction, CheckoutRepositoryError>>;
  markUnknown(
    transactionId: string,
    updatedAt: string,
    check: ReconciliationCheck,
  ): Promise<Result<Transaction, CheckoutRepositoryError>>;
  finalize(
    transactionId: string,
    status: Exclude<PaymentStatus, 'PENDING'>,
    providerStatus: ProviderStatus,
    recoveryCode: Transaction['recoveryCode'],
    updatedAt: string,
  ): Promise<Result<Transaction, CheckoutRepositoryError>>;
  findTransaction(
    transactionId: string,
  ): Promise<Result<Transaction | null, CheckoutRepositoryError>>;
  findTransactionByProviderId(
    providerId: string,
  ): Promise<Result<Transaction | null, CheckoutRepositoryError>>;
  recordWebhook(eventHash: string): Promise<Result<'NEW' | 'DUPLICATE', CheckoutRepositoryError>>;
  findOldestPendingAcceptedAt(): Promise<Result<string | null, CheckoutRepositoryError>>;
  claimDue(
    now: string,
    leaseUntil: string,
    limit: number,
  ): Promise<Result<readonly Transaction[], CheckoutRepositoryError>>;
  findDelivery(deliveryId: string): Promise<Result<Delivery | null, CheckoutRepositoryError>>;
}

export const CHECKOUT_REPOSITORY = Symbol('CHECKOUT_REPOSITORY');
