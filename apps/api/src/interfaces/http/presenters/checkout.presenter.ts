import type {
  CheckoutView,
  TransactionView,
} from '../../../application/use-cases/checkout-service';
import type {
  Checkout,
  Delivery,
  DeliveryDetails,
  PaymentSubmission,
} from '../../../domain/checkout/checkout';
import { presentProduct } from './product.presenter';

export const presentCheckoutCreated = (checkout: Checkout) => ({
  checkoutId: checkout.checkoutId,
  status: 'DRAFT' as const,
  version: checkout.version,
  quote: checkout.quote,
  expiresAt: checkout.expiresAt,
});

export const presentCheckout = ({ checkout, product }: CheckoutView) => ({
  checkoutId: checkout.checkoutId,
  status: checkout.status,
  version: checkout.version,
  product: presentProduct(product),
  quote: checkout.quote,
  customer: checkout.customer ?? null,
  deliveryDetails: checkout.deliveryDetails ?? null,
  activeTransactionId: checkout.activeTransactionId ?? null,
  expiresAt: checkout.expiresAt,
});

export const presentCustomer = (checkout: Checkout) => checkout.customer;

export const presentDeliveryDetails = (checkout: Checkout): DeliveryDetails | undefined =>
  checkout.deliveryDetails;

export const presentSubmission = (submission: PaymentSubmission): PaymentSubmission => submission;

export const presentTransaction = ({ transaction, checkout, allowedActions }: TransactionView) => ({
  transactionId: transaction.transactionId,
  checkoutId: transaction.checkoutId,
  checkoutStatus: checkout.status,
  paymentStatus: transaction.paymentStatus,
  dispatchPhase: transaction.dispatchPhase,
  providerStatus: transaction.providerStatus,
  reservationStatus: transaction.reservationStatus,
  integrityStatus: transaction.integrityStatus,
  ...(transaction.recoveryCode === undefined ? {} : { recoveryCode: transaction.recoveryCode }),
  ...(transaction.deliveryId === undefined ? {} : { deliveryId: transaction.deliveryId }),
  statusUrl: `/api/v1/transactions/${transaction.transactionId}`,
  allowedActions,
  ...(transaction.paymentStatus === 'PENDING' ? { retryAfterSeconds: 1 } : {}),
  acceptedAt: transaction.acceptedAt,
  updatedAt: transaction.updatedAt,
});

export const presentDelivery = (delivery: Delivery): Delivery => delivery;
