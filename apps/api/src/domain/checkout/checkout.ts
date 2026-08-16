export type CheckoutStatus =
  'DRAFT' | 'READY' | 'PAYMENT_PENDING' | 'PAID' | 'PAYMENT_FAILED' | 'EXPIRED';

export interface Money {
  readonly amountInCents: number;
  readonly currency: 'COP';
}

export interface Quote {
  readonly quoteId: string;
  readonly version: number;
  readonly productId: string;
  readonly quantity: 1;
  readonly subtotal: Money;
  readonly baseFee: Money;
  readonly deliveryFee: Money;
  readonly total: Money;
  readonly expiresAt: string;
}

export interface Customer {
  readonly customerId: string;
  readonly checkoutId: string;
  readonly version: number;
  readonly fullName: string;
  readonly email: string;
  readonly phone: string;
}

export interface DeliveryDetails {
  readonly checkoutId: string;
  readonly version: number;
  readonly addressLine1: string;
  readonly addressLine2?: string;
  readonly city: string;
  readonly region: string;
  readonly postalCode?: string;
  readonly deliveryInstructions?: string;
}

export interface Checkout {
  readonly checkoutId: string;
  readonly status: CheckoutStatus;
  readonly version: number;
  readonly capabilityHash: string;
  readonly productId: string;
  readonly quote: Quote;
  readonly customer?: Customer;
  readonly deliveryDetails?: DeliveryDetails;
  readonly activeTransactionId?: string;
  readonly expiresAt: string;
}

export type PaymentStatus = 'PENDING' | 'APPROVED' | 'DECLINED' | 'VOIDED' | 'ERROR';
export type DispatchPhase = 'NOT_SENT' | 'SENDING' | 'ACKNOWLEDGED' | 'UNKNOWN' | 'NOT_SENT_FAILED';
export type ProviderStatus = PaymentStatus | null;
export type ReservationStatus = 'ACTIVE' | 'CONSUMED' | 'RELEASED';
export type IntegrityStatus = 'OK' | 'APPROVED_INVENTORY_CONFLICT' | 'FINAL_STATE_CONFLICT';
export type RecoveryCode =
  | 'PAYMENT_TOKEN_REJECTED'
  | 'PROVIDER_NOT_SENT'
  | 'PROVIDER_OUTCOME_UNKNOWN'
  | 'STATE_TRANSITION_CONFLICT'
  | 'RATE_LIMITED'
  | 'INTERNAL_ERROR';
export type AllowedAction =
  'QUERY' | 'WAIT' | 'RETURN_TO_PRODUCT' | 'START_NEW_CHECKOUT' | 'CONTACT_SUPPORT';
export interface AcceptanceEvidence {
  readonly termsVersion: string;
  readonly termsContractHash: string;
  readonly personalDataVersion: string;
  readonly personalDataContractHash: string;
  readonly acceptedAt: string;
}

export interface Transaction {
  readonly transactionId: string;
  readonly checkoutId: string;
  readonly providerReference: string;
  readonly providerId?: string;
  readonly paymentStatus: PaymentStatus;
  readonly dispatchPhase: DispatchPhase;
  readonly providerStatus: ProviderStatus;
  readonly reservationStatus: ReservationStatus;
  readonly integrityStatus: IntegrityStatus;
  readonly recoveryCode?: RecoveryCode;
  readonly deliveryId?: string;
  readonly acceptanceEvidence: AcceptanceEvidence;
  readonly acceptedAt: string;
  readonly updatedAt: string;
  readonly attempts: number;
  readonly lastCheckedAt?: string;
  readonly nextCheckAt?: string;
  readonly amountInCents: number;
  readonly currency: 'COP';
  readonly effectsApplied: boolean;
}

export interface PaymentSubmission {
  readonly transactionId: string;
  readonly statusUrl: string;
  readonly submissionState: 'ACCEPTED';
  readonly acceptedAt: string;
}

export interface Delivery {
  readonly deliveryId: string;
  readonly checkoutId: string;
  readonly transactionId: string;
  readonly status: 'CREATED' | 'ASSIGNED' | 'CANCELLED';
  readonly destination: Omit<DeliveryDetails, 'checkoutId' | 'version'>;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export const etagFor = (version: number): string => `"checkout-v${version}"`;

export const isTerminalPayment = (status: PaymentStatus): boolean => status !== 'PENDING';

export const checkoutStatusForPayment = (status: PaymentStatus): CheckoutStatus =>
  status === 'PENDING' ? 'PAYMENT_PENDING' : status === 'APPROVED' ? 'PAID' : 'PAYMENT_FAILED';

export const allowedActionsFor = (transaction: Transaction): readonly AllowedAction[] => {
  if (transaction.paymentStatus === 'PENDING') {
    return ['QUERY', 'WAIT', 'RETURN_TO_PRODUCT'];
  }
  if (transaction.integrityStatus !== 'OK') {
    return ['QUERY', 'RETURN_TO_PRODUCT', 'CONTACT_SUPPORT'];
  }
  if (transaction.paymentStatus === 'APPROVED') {
    return ['QUERY', 'RETURN_TO_PRODUCT'];
  }
  const isSafelyReleasedFailure =
    (transaction.paymentStatus === 'DECLINED' ||
      transaction.paymentStatus === 'ERROR' ||
      transaction.paymentStatus === 'VOIDED') &&
    transaction.effectsApplied &&
    transaction.reservationStatus === 'RELEASED' &&
    transaction.deliveryId === undefined;
  return isSafelyReleasedFailure
    ? ['QUERY', 'RETURN_TO_PRODUCT', 'START_NEW_CHECKOUT']
    : ['QUERY', 'RETURN_TO_PRODUCT', 'CONTACT_SUPPORT'];
};
