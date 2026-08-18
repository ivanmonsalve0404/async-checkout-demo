import {
  GetCommand,
  QueryCommand,
  TransactWriteCommand,
  UpdateCommand,
  type DynamoDBDocumentClient,
} from '@aws-sdk/lib-dynamodb';
import type { TransactWriteCommandInput } from '@aws-sdk/lib-dynamodb';
import type {
  CheckoutRepository,
  CheckoutRepositoryError,
  PreparedPayment,
  ReconciliationCheck,
} from '../../application/ports/checkout-repository';
import type { Result } from '../../application/result/result';
import { err, ok } from '../../application/result/result';
import {
  checkoutStatusForPayment,
  isTerminalPayment,
  type Checkout,
  type Customer,
  type Delivery,
  type DeliveryDetails,
  type DispatchPhase,
  type PaymentStatus,
  type PaymentSubmission,
  type ProviderStatus,
  type Quote,
  type ReservationStatus,
  type Transaction,
} from '../../domain/checkout/checkout';

type StoredCheckoutMeta = Omit<Checkout, 'quote' | 'customer' | 'deliveryDetails'> &
  Readonly<{
    PK: string;
    SK: 'META';
    itemType: 'CHECKOUT';
    quoteId: string;
    schemaVersion: 1;
  }>;
type StoredQuote = Quote &
  Readonly<{ PK: string; SK: string; itemType: 'QUOTE'; schemaVersion: 1 }>;
type StoredCustomer = Customer &
  Readonly<{ PK: string; SK: 'CUSTOMER'; itemType: 'CUSTOMER'; schemaVersion: 1 }>;
type StoredDeliveryDetails = DeliveryDetails &
  Readonly<{
    PK: string;
    SK: 'DELIVERY_DETAILS';
    itemType: 'DELIVERY_DETAILS';
    schemaVersion: 1;
  }>;
type StoredPayment = Transaction &
  Readonly<{
    PK: string;
    SK: string;
    itemType: 'PAYMENT';
    idempotencyKeyHash: string;
    schemaVersion: 1;
    GSI1PK?: 'RECON#DUE';
    GSI1SK?: string;
    GSI2PK?: 'PAYMENT#PENDING';
    GSI2SK?: string;
    leaseUntil?: string;
  }>;
type StoredReservation = Readonly<{
  PK: string;
  SK: string;
  itemType: 'RESERVATION';
  reservationId: string;
  checkoutId: string;
  transactionId: string;
  productId: string;
  quantity: 1;
  status: ReservationStatus;
  expiresAt: string;
  updatedAt: string;
  schemaVersion: 1;
}>;
type StoredIdempotency = Readonly<{
  PK: string;
  SK: string;
  itemType: 'IDEMPOTENCY';
  operation: 'SUBMIT_PAYMENT';
  keyHash: string;
  semanticHash: string;
  status: 'IN_PROGRESS' | 'FINAL';
  checkoutId: string;
  transactionId: string;
  submission: PaymentSubmission;
  schemaVersion: 1;
}>;
type StoredDelivery = Delivery &
  Readonly<{ PK: string; SK: string; itemType: 'DELIVERY'; schemaVersion: 1 }>;
type StoredLock = Readonly<{
  PK: string;
  SK: 'LOCK';
  itemType: 'UNIQUE_LOCK';
  kind: 'TRANSACTION' | 'PROVIDER' | 'DELIVERY';
  checkoutId: string;
  transactionId: string;
  schemaVersion: 1;
}>;

type LookupKind = StoredLock['kind'];
type DispatchClaim = Readonly<{ kind: 'CLAIMED' | 'NOT_LEADER'; transaction: Transaction }>;
type TransactItem = NonNullable<TransactWriteCommandInput['TransactItems']>[number];

const paymentStatuses = new Set<PaymentStatus>([
  'PENDING',
  'APPROVED',
  'DECLINED',
  'VOIDED',
  'ERROR',
]);
const dispatchPhases = new Set<DispatchPhase>([
  'NOT_SENT',
  'SENDING',
  'ACKNOWLEDGED',
  'UNKNOWN',
  'NOT_SENT_FAILED',
]);
const reservationStatuses = new Set<ReservationStatus>(['ACTIVE', 'CONSUMED', 'RELEASED']);
const checkoutStatuses = new Set<Checkout['status']>([
  'DRAFT',
  'READY',
  'PAYMENT_PENDING',
  'PAID',
  'PAYMENT_FAILED',
  'EXPIRED',
]);
const recoveryCodes = new Set<NonNullable<Transaction['recoveryCode']>>([
  'PAYMENT_TOKEN_REJECTED',
  'PROVIDER_NOT_SENT',
  'PROVIDER_OUTCOME_UNKNOWN',
  'STATE_TRANSITION_CONFLICT',
  'RATE_LIMITED',
  'INTERNAL_ERROR',
]);

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null;
const optionalString = (value: unknown): boolean =>
  value === undefined || typeof value === 'string';
const isMoney = (value: unknown): value is Quote['total'] =>
  isRecord(value) &&
  typeof value.amountInCents === 'number' &&
  Number.isSafeInteger(value.amountInCents) &&
  value.amountInCents >= 0 &&
  value.currency === 'COP';

const isAcceptanceEvidence = (value: unknown): value is Transaction['acceptanceEvidence'] =>
  isRecord(value) &&
  Object.keys(value).length === 5 &&
  typeof value.termsVersion === 'string' &&
  typeof value.termsContractHash === 'string' &&
  typeof value.personalDataVersion === 'string' &&
  typeof value.personalDataContractHash === 'string' &&
  typeof value.acceptedAt === 'string';

const isQuoteItem = (value: unknown): value is StoredQuote => {
  if (!isRecord(value)) return false;
  return (
    value.itemType === 'QUOTE' &&
    typeof value.PK === 'string' &&
    typeof value.SK === 'string' &&
    value.schemaVersion === 1 &&
    typeof value.quoteId === 'string' &&
    typeof value.version === 'number' &&
    typeof value.productId === 'string' &&
    value.quantity === 1 &&
    isMoney(value.subtotal) &&
    isMoney(value.baseFee) &&
    isMoney(value.deliveryFee) &&
    isMoney(value.total) &&
    typeof value.expiresAt === 'string'
  );
};

const isCheckoutMeta = (value: unknown): value is StoredCheckoutMeta => {
  if (!isRecord(value)) return false;
  return (
    value.itemType === 'CHECKOUT' &&
    value.SK === 'META' &&
    value.schemaVersion === 1 &&
    typeof value.checkoutId === 'string' &&
    typeof value.status === 'string' &&
    checkoutStatuses.has(value.status as Checkout['status']) &&
    typeof value.version === 'number' &&
    Number.isSafeInteger(value.version) &&
    typeof value.capabilityHash === 'string' &&
    typeof value.productId === 'string' &&
    typeof value.quoteId === 'string' &&
    optionalString(value.activeTransactionId) &&
    typeof value.expiresAt === 'string'
  );
};

const isCustomerItem = (value: unknown): value is StoredCustomer =>
  isRecord(value) &&
  value.itemType === 'CUSTOMER' &&
  value.SK === 'CUSTOMER' &&
  value.schemaVersion === 1 &&
  typeof value.customerId === 'string' &&
  typeof value.checkoutId === 'string' &&
  typeof value.version === 'number' &&
  typeof value.fullName === 'string' &&
  typeof value.email === 'string' &&
  typeof value.phone === 'string';

const isDeliveryDetailsItem = (value: unknown): value is StoredDeliveryDetails =>
  isRecord(value) &&
  value.itemType === 'DELIVERY_DETAILS' &&
  value.SK === 'DELIVERY_DETAILS' &&
  value.schemaVersion === 1 &&
  typeof value.checkoutId === 'string' &&
  typeof value.version === 'number' &&
  typeof value.addressLine1 === 'string' &&
  optionalString(value.addressLine2) &&
  typeof value.city === 'string' &&
  typeof value.region === 'string' &&
  optionalString(value.postalCode) &&
  optionalString(value.deliveryInstructions);

const isPaymentItem = (value: unknown): value is StoredPayment => {
  if (!isRecord(value)) return false;
  return (
    value.itemType === 'PAYMENT' &&
    value.schemaVersion === 1 &&
    typeof value.transactionId === 'string' &&
    typeof value.checkoutId === 'string' &&
    typeof value.providerReference === 'string' &&
    optionalString(value.providerId) &&
    typeof value.paymentStatus === 'string' &&
    paymentStatuses.has(value.paymentStatus as PaymentStatus) &&
    typeof value.dispatchPhase === 'string' &&
    dispatchPhases.has(value.dispatchPhase as DispatchPhase) &&
    (value.providerStatus === null ||
      (typeof value.providerStatus === 'string' &&
        paymentStatuses.has(value.providerStatus as PaymentStatus))) &&
    typeof value.reservationStatus === 'string' &&
    reservationStatuses.has(value.reservationStatus as ReservationStatus) &&
    (value.integrityStatus === 'OK' ||
      value.integrityStatus === 'APPROVED_INVENTORY_CONFLICT' ||
      value.integrityStatus === 'FINAL_STATE_CONFLICT') &&
    (value.recoveryCode === undefined ||
      (typeof value.recoveryCode === 'string' &&
        recoveryCodes.has(value.recoveryCode as NonNullable<Transaction['recoveryCode']>))) &&
    optionalString(value.deliveryId) &&
    typeof value.acceptedAt === 'string' &&
    isAcceptanceEvidence(value.acceptanceEvidence) &&
    typeof value.updatedAt === 'string' &&
    typeof value.attempts === 'number' &&
    Number.isSafeInteger(value.attempts) &&
    value.attempts >= 0 &&
    optionalString(value.lastCheckedAt) &&
    optionalString(value.nextCheckAt) &&
    typeof value.amountInCents === 'number' &&
    Number.isSafeInteger(value.amountInCents) &&
    value.amountInCents >= 0 &&
    value.currency === 'COP' &&
    typeof value.effectsApplied === 'boolean' &&
    typeof value.idempotencyKeyHash === 'string'
  );
};
type ReconcileCandidate = Pick<
  StoredPayment,
  'PK' | 'SK' | 'checkoutId' | 'transactionId' | 'dispatchPhase' | 'paymentStatus'
>;

const isReconcileCandidate = (value: unknown): value is ReconcileCandidate =>
  isRecord(value) &&
  typeof value.PK === 'string' &&
  typeof value.SK === 'string' &&
  typeof value.checkoutId === 'string' &&
  typeof value.transactionId === 'string' &&
  typeof value.dispatchPhase === 'string' &&
  dispatchPhases.has(value.dispatchPhase as DispatchPhase) &&
  typeof value.paymentStatus === 'string' &&
  paymentStatuses.has(value.paymentStatus as PaymentStatus);

type OldestPendingProjection = Pick<StoredPayment, 'acceptedAt' | 'paymentStatus'>;

const isOldestPendingProjection = (value: unknown): value is OldestPendingProjection =>
  isRecord(value) && value.paymentStatus === 'PENDING' && typeof value.acceptedAt === 'string';

const isIdempotencyItem = (value: unknown): value is StoredIdempotency =>
  isRecord(value) &&
  isRecord(value.submission) &&
  value.itemType === 'IDEMPOTENCY' &&
  value.operation === 'SUBMIT_PAYMENT' &&
  value.schemaVersion === 1 &&
  typeof value.keyHash === 'string' &&
  typeof value.semanticHash === 'string' &&
  (value.status === 'IN_PROGRESS' || value.status === 'FINAL') &&
  typeof value.checkoutId === 'string' &&
  typeof value.transactionId === 'string' &&
  value.submission.transactionId === value.transactionId &&
  typeof value.submission.statusUrl === 'string' &&
  value.submission.submissionState === 'ACCEPTED' &&
  typeof value.submission.acceptedAt === 'string';

const isDeliveryItem = (value: unknown): value is StoredDelivery =>
  isRecord(value) &&
  isRecord(value.destination) &&
  value.itemType === 'DELIVERY' &&
  value.schemaVersion === 1 &&
  typeof value.deliveryId === 'string' &&
  typeof value.checkoutId === 'string' &&
  typeof value.transactionId === 'string' &&
  (value.status === 'CREATED' || value.status === 'ASSIGNED' || value.status === 'CANCELLED') &&
  typeof value.destination.addressLine1 === 'string' &&
  optionalString(value.destination.addressLine2) &&
  typeof value.destination.city === 'string' &&
  typeof value.destination.region === 'string' &&
  optionalString(value.destination.postalCode) &&
  optionalString(value.destination.deliveryInstructions) &&
  typeof value.createdAt === 'string' &&
  typeof value.updatedAt === 'string';

const isLockItem = (value: unknown, kind: LookupKind): value is StoredLock =>
  isRecord(value) &&
  value.itemType === 'UNIQUE_LOCK' &&
  value.kind === kind &&
  value.SK === 'LOCK' &&
  value.schemaVersion === 1 &&
  typeof value.checkoutId === 'string' &&
  typeof value.transactionId === 'string';

const isReservationItem = (value: unknown): value is StoredReservation =>
  isRecord(value) &&
  value.itemType === 'RESERVATION' &&
  value.schemaVersion === 1 &&
  typeof value.reservationId === 'string' &&
  typeof value.checkoutId === 'string' &&
  typeof value.transactionId === 'string' &&
  typeof value.productId === 'string' &&
  value.quantity === 1 &&
  typeof value.status === 'string' &&
  reservationStatuses.has(value.status as ReservationStatus) &&
  typeof value.expiresAt === 'string' &&
  typeof value.updatedAt === 'string';

const isConditionalFailure = (value: unknown): boolean =>
  isRecord(value) && value.name === 'ConditionalCheckFailedException';
const isTransactionCanceled = (value: unknown): boolean =>
  isRecord(value) && value.name === 'TransactionCanceledException';
const cancellationCode = (value: unknown, index: number): string | undefined => {
  if (!isRecord(value) || !Array.isArray(value.CancellationReasons)) return undefined;
  const reasons: unknown[] = value.CancellationReasons;
  const reason = reasons[index];
  return isRecord(reason) && typeof reason.Code === 'string' ? reason.Code : undefined;
};
const conditionalAt = (value: unknown, index: number): boolean =>
  cancellationCode(value, index) === 'ConditionalCheckFailed';

const checkoutPk = (checkoutId: string): string => 'CHECKOUT#' + checkoutId;
const paymentSk = (transactionId: string): string => 'PAYMENT#' + transactionId;
const reservationSk = (transactionId: string): string => 'RESERVATION#' + transactionId;
const deliverySk = (deliveryId: string): string => 'DELIVERY#' + deliveryId;
const idempotencySk = (keyHash: string): string => 'IDEMPOTENCY#SUBMIT_PAYMENT#' + keyHash;

const checkoutMetaItem = (checkout: Checkout): StoredCheckoutMeta => {
  const { quote, customer, deliveryDetails, ...meta } = checkout;
  void customer;
  void deliveryDetails;
  return {
    ...meta,
    PK: checkoutPk(checkout.checkoutId),
    SK: 'META',
    itemType: 'CHECKOUT',
    quoteId: quote.quoteId,
    schemaVersion: 1,
  };
};

const quoteItem = (checkoutId: string, quote: Quote): StoredQuote => ({
  ...quote,
  PK: checkoutPk(checkoutId),
  SK: 'QUOTE#' + quote.quoteId,
  itemType: 'QUOTE',
  schemaVersion: 1,
});

const customerItem = (customer: Customer): StoredCustomer => ({
  ...customer,
  PK: checkoutPk(customer.checkoutId),
  SK: 'CUSTOMER',
  itemType: 'CUSTOMER',
  schemaVersion: 1,
});

const deliveryDetailsItem = (details: DeliveryDetails): StoredDeliveryDetails => ({
  ...details,
  PK: checkoutPk(details.checkoutId),
  SK: 'DELIVERY_DETAILS',
  itemType: 'DELIVERY_DETAILS',
  schemaVersion: 1,
});

const transactionFromItem = (item: StoredPayment): Transaction => {
  const {
    PK,
    SK,
    itemType,
    idempotencyKeyHash,
    schemaVersion,
    GSI1PK,
    GSI1SK,
    GSI2PK,
    GSI2SK,
    leaseUntil,
    ...transaction
  } = item;
  void PK;
  void SK;
  void itemType;
  void idempotencyKeyHash;
  void schemaVersion;
  void GSI1PK;
  void GSI1SK;
  void GSI2PK;
  void GSI2SK;
  void leaseUntil;
  return transaction;
};

const deliveryFromItem = (item: StoredDelivery): Delivery => {
  const { PK, SK, itemType, schemaVersion, ...delivery } = item;
  void PK;
  void SK;
  void itemType;
  void schemaVersion;
  return delivery;
};

export class DynamoDbCheckoutRepository implements CheckoutRepository {
  public constructor(
    private readonly client: DynamoDBDocumentClient,
    private readonly catalogTableName: string,
    private readonly checkoutTableName: string,
    private readonly hmacLookup: (value: string) => string,
  ) {}

  public async create(checkout: Checkout): Promise<Result<Checkout, CheckoutRepositoryError>> {
    try {
      await this.client.send(
        new TransactWriteCommand({
          TransactItems: [
            {
              Put: {
                TableName: this.checkoutTableName,
                Item: checkoutMetaItem(checkout),
                ConditionExpression: 'attribute_not_exists(PK) AND attribute_not_exists(SK)',
              },
            },
            {
              Put: {
                TableName: this.checkoutTableName,
                Item: quoteItem(checkout.checkoutId, checkout.quote),
                ConditionExpression: 'attribute_not_exists(PK) AND attribute_not_exists(SK)',
              },
            },
            ...(checkout.customer === undefined
              ? []
              : [
                  {
                    Put: {
                      TableName: this.checkoutTableName,
                      Item: customerItem(checkout.customer),
                      ConditionExpression: 'attribute_not_exists(PK) AND attribute_not_exists(SK)',
                    },
                  },
                ]),
            ...(checkout.deliveryDetails === undefined
              ? []
              : [
                  {
                    Put: {
                      TableName: this.checkoutTableName,
                      Item: deliveryDetailsItem(checkout.deliveryDetails),
                      ConditionExpression: 'attribute_not_exists(PK) AND attribute_not_exists(SK)',
                    },
                  },
                ]),
          ],
        }),
      );
      return ok(checkout);
    } catch {
      return err({ code: 'REPOSITORY_UNAVAILABLE' });
    }
  }

  public async findCheckout(
    checkoutId: string,
  ): Promise<Result<Checkout | null, CheckoutRepositoryError>> {
    try {
      const response = await this.client.send(
        new QueryCommand({
          TableName: this.checkoutTableName,
          KeyConditionExpression: 'PK = :pk',
          ExpressionAttributeValues: { ':pk': checkoutPk(checkoutId) },
          ConsistentRead: true,
        }),
      );
      const items = response.Items ?? [];
      const rawMeta = items.find((item) => item.SK === 'META');
      if (rawMeta === undefined) return ok(null);
      if (!isCheckoutMeta(rawMeta)) return err({ code: 'REPOSITORY_UNAVAILABLE' });
      const rawQuote = items.find((item) => item.SK === 'QUOTE#' + rawMeta.quoteId);
      if (!isQuoteItem(rawQuote)) return err({ code: 'REPOSITORY_UNAVAILABLE' });
      const rawCustomer = items.find((item) => item.SK === 'CUSTOMER');
      const rawDetails = items.find((item) => item.SK === 'DELIVERY_DETAILS');
      if (
        (rawCustomer !== undefined && !isCustomerItem(rawCustomer)) ||
        (rawDetails !== undefined && !isDeliveryDetailsItem(rawDetails))
      ) {
        return err({ code: 'REPOSITORY_UNAVAILABLE' });
      }
      const { PK, SK, itemType, quoteId, schemaVersion, ...meta } = rawMeta;
      void PK;
      void SK;
      void itemType;
      void quoteId;
      void schemaVersion;
      const {
        PK: storedPk,
        SK: storedSk,
        itemType: storedType,
        schemaVersion: storedSchema,
        ...quote
      } = rawQuote;
      void storedPk;
      void storedSk;
      void storedType;
      void storedSchema;
      const customer =
        rawCustomer === undefined
          ? {}
          : {
              customer: {
                customerId: rawCustomer.customerId,
                checkoutId: rawCustomer.checkoutId,
                version: rawCustomer.version,
                fullName: rawCustomer.fullName,
                email: rawCustomer.email,
                phone: rawCustomer.phone,
              },
            };
      const deliveryDetails =
        rawDetails === undefined
          ? {}
          : {
              deliveryDetails: {
                checkoutId: rawDetails.checkoutId,
                version: rawDetails.version,
                addressLine1: rawDetails.addressLine1,
                ...(rawDetails.addressLine2 === undefined
                  ? {}
                  : { addressLine2: rawDetails.addressLine2 }),
                city: rawDetails.city,
                region: rawDetails.region,
                ...(rawDetails.postalCode === undefined
                  ? {}
                  : { postalCode: rawDetails.postalCode }),
                ...(rawDetails.deliveryInstructions === undefined
                  ? {}
                  : { deliveryInstructions: rawDetails.deliveryInstructions }),
              },
            };
      return ok({ ...meta, quote, ...customer, ...deliveryDetails });
    } catch {
      return err({ code: 'REPOSITORY_UNAVAILABLE' });
    }
  }

  public async replaceCustomer(
    checkoutId: string,
    capabilityHash: string,
    expectedVersion: number,
    customer: Omit<Customer, 'version'>,
  ): Promise<Result<Checkout, CheckoutRepositoryError>> {
    const found = await this.findCheckout(checkoutId);
    if (!found.ok || found.value === null) {
      return found.ok ? err({ code: 'CHECKOUT_NOT_FOUND' }) : found;
    }
    const current = found.value;
    if (current.capabilityHash !== capabilityHash) return err({ code: 'CHECKOUT_NOT_FOUND' });
    if (current.version !== expectedVersion) return err({ code: 'VERSION_MISMATCH' });
    if (current.activeTransactionId !== undefined) {
      return err({ code: 'PAYMENT_ALREADY_IN_PROGRESS' });
    }
    const version = expectedVersion + 1;
    const updated: Checkout = {
      ...current,
      version,
      status: current.deliveryDetails === undefined ? 'DRAFT' : 'READY',
      customer: { ...customer, version },
    };
    try {
      await this.client.send(
        new TransactWriteCommand({
          TransactItems: [
            {
              Update: {
                TableName: this.checkoutTableName,
                Key: { PK: checkoutPk(checkoutId), SK: 'META' },
                ConditionExpression:
                  '#capabilityHash = :capabilityHash AND #version = :expectedVersion AND attribute_not_exists(#activeTransactionId)',
                UpdateExpression: 'SET #version = :version, #status = :status',
                ExpressionAttributeNames: {
                  '#activeTransactionId': 'activeTransactionId',
                  '#capabilityHash': 'capabilityHash',
                  '#status': 'status',
                  '#version': 'version',
                },
                ExpressionAttributeValues: {
                  ':capabilityHash': capabilityHash,
                  ':expectedVersion': expectedVersion,
                  ':status': updated.status,
                  ':version': version,
                },
              },
            },
            {
              Put: {
                TableName: this.checkoutTableName,
                Item: customerItem({ ...customer, version }),
              },
            },
          ],
        }),
      );
      return ok(updated);
    } catch (error: unknown) {
      return this.classifyCheckoutWriteFailure(error, checkoutId, capabilityHash, expectedVersion);
    }
  }

  public async replaceDeliveryDetails(
    checkoutId: string,
    capabilityHash: string,
    expectedVersion: number,
    details: Omit<DeliveryDetails, 'version'>,
  ): Promise<Result<Checkout, CheckoutRepositoryError>> {
    const found = await this.findCheckout(checkoutId);
    if (!found.ok || found.value === null) {
      return found.ok ? err({ code: 'CHECKOUT_NOT_FOUND' }) : found;
    }
    const current = found.value;
    if (current.capabilityHash !== capabilityHash) return err({ code: 'CHECKOUT_NOT_FOUND' });
    if (current.version !== expectedVersion) return err({ code: 'VERSION_MISMATCH' });
    if (current.activeTransactionId !== undefined) {
      return err({ code: 'PAYMENT_ALREADY_IN_PROGRESS' });
    }
    const version = expectedVersion + 1;
    const updated: Checkout = {
      ...current,
      version,
      status: current.customer === undefined ? 'DRAFT' : 'READY',
      deliveryDetails: { ...details, version },
    };
    try {
      await this.client.send(
        new TransactWriteCommand({
          TransactItems: [
            {
              Update: {
                TableName: this.checkoutTableName,
                Key: { PK: checkoutPk(checkoutId), SK: 'META' },
                ConditionExpression:
                  '#capabilityHash = :capabilityHash AND #version = :expectedVersion AND attribute_not_exists(#activeTransactionId)',
                UpdateExpression: 'SET #version = :version, #status = :status',
                ExpressionAttributeNames: {
                  '#activeTransactionId': 'activeTransactionId',
                  '#capabilityHash': 'capabilityHash',
                  '#status': 'status',
                  '#version': 'version',
                },
                ExpressionAttributeValues: {
                  ':capabilityHash': capabilityHash,
                  ':expectedVersion': expectedVersion,
                  ':status': updated.status,
                  ':version': version,
                },
              },
            },
            {
              Put: {
                TableName: this.checkoutTableName,
                Item: deliveryDetailsItem({ ...details, version }),
              },
            },
          ],
        }),
      );
      return ok(updated);
    } catch (error: unknown) {
      return this.classifyCheckoutWriteFailure(error, checkoutId, capabilityHash, expectedVersion);
    }
  }

  public async findIdempotency(
    input: Readonly<{ checkoutId: string; keyHash: string; semanticHash: string }>,
  ): Promise<Result<PreparedPayment | null, CheckoutRepositoryError>> {
    try {
      const response = await this.client.send(
        new GetCommand({
          TableName: this.checkoutTableName,
          Key: { PK: checkoutPk(input.checkoutId), SK: idempotencySk(input.keyHash) },
          ConsistentRead: true,
        }),
      );
      if (response.Item === undefined) return ok(null);
      if (!isIdempotencyItem(response.Item)) {
        return err({ code: 'REPOSITORY_UNAVAILABLE' });
      }
      if (response.Item.semanticHash !== input.semanticHash) {
        return err({ code: 'IDEMPOTENCY_CONFLICT' });
      }
      const [checkout, payment] = await Promise.all([
        this.findCheckout(input.checkoutId),
        this.getStoredPayment(input.checkoutId, response.Item.transactionId),
      ]);
      if (!checkout.ok || checkout.value === null || !payment.ok || payment.value === null) {
        return err({ code: 'REPOSITORY_UNAVAILABLE' });
      }
      return ok({
        kind: 'REPLAY',
        checkout: checkout.value,
        transaction: transactionFromItem(payment.value),
        submission: response.Item.submission,
      });
    } catch {
      return err({ code: 'REPOSITORY_UNAVAILABLE' });
    }
  }

  public async preparePayment(
    input: Readonly<{
      checkoutId: string;
      capabilityHash: string;
      expectedVersion: number;
      keyHash: string;
      semanticHash: string;
      transaction: Transaction;
      submission: PaymentSubmission;
    }>,
  ): Promise<Result<PreparedPayment, CheckoutRepositoryError>> {
    const existing = await this.findIdempotency(input);
    if (!existing.ok) return err(existing.error);
    if (existing.value !== null) return ok(existing.value);
    const found = await this.findCheckout(input.checkoutId);
    if (!found.ok || found.value === null) {
      return found.ok ? err({ code: 'CHECKOUT_NOT_FOUND' }) : found;
    }
    const checkout = found.value;
    if (checkout.capabilityHash !== input.capabilityHash) {
      return err({ code: 'CHECKOUT_NOT_FOUND' });
    }
    if (checkout.version !== input.expectedVersion) {
      return err({ code: 'VERSION_MISMATCH' });
    }
    if (checkout.activeTransactionId !== undefined) {
      return err({ code: 'PAYMENT_ALREADY_IN_PROGRESS' });
    }
    const updatedCheckout: Checkout = {
      ...checkout,
      status: 'PAYMENT_PENDING',
      version: checkout.version + 1,
      activeTransactionId: input.transaction.transactionId,
    };
    const payment: StoredPayment = {
      ...input.transaction,
      PK: checkoutPk(input.checkoutId),
      SK: paymentSk(input.transaction.transactionId),
      GSI1PK: 'RECON#DUE',
      GSI1SK:
        (input.transaction.nextCheckAt ?? input.transaction.acceptedAt) +
        '#' +
        input.transaction.transactionId,
      GSI2PK: 'PAYMENT#PENDING',
      GSI2SK: input.transaction.acceptedAt + '#' + input.transaction.transactionId,
      itemType: 'PAYMENT',
      idempotencyKeyHash: input.keyHash,
      schemaVersion: 1,
    };
    const reservation: StoredReservation = {
      PK: checkoutPk(input.checkoutId),
      SK: reservationSk(input.transaction.transactionId),
      itemType: 'RESERVATION',
      reservationId: input.transaction.transactionId,
      checkoutId: input.checkoutId,
      transactionId: input.transaction.transactionId,
      productId: checkout.productId,
      quantity: 1,
      status: 'ACTIVE',
      expiresAt: checkout.expiresAt,
      updatedAt: input.transaction.acceptedAt,
      schemaVersion: 1,
    };
    const idempotency: StoredIdempotency = {
      PK: checkoutPk(input.checkoutId),
      SK: idempotencySk(input.keyHash),
      itemType: 'IDEMPOTENCY',
      operation: 'SUBMIT_PAYMENT',
      keyHash: input.keyHash,
      semanticHash: input.semanticHash,
      status: 'IN_PROGRESS',
      checkoutId: input.checkoutId,
      transactionId: input.transaction.transactionId,
      submission: input.submission,
      schemaVersion: 1,
    };
    try {
      await this.client.send(
        new TransactWriteCommand({
          TransactItems: [
            {
              Update: {
                TableName: this.catalogTableName,
                Key: { PK: 'PRODUCT#' + checkout.productId, SK: 'META' },
                ConditionExpression:
                  'attribute_exists(PK) AND #active = :active AND #available >= :one AND #reserved < #onHand',
                UpdateExpression:
                  'SET #reserved = #reserved + :one, #available = #available - :one, #version = #version + :one, #updatedAt = :updatedAt',
                ExpressionAttributeNames: {
                  '#active': 'active',
                  '#available': 'available',
                  '#onHand': 'onHand',
                  '#reserved': 'reserved',
                  '#updatedAt': 'updatedAt',
                  '#version': 'version',
                },
                ExpressionAttributeValues: {
                  ':active': true,
                  ':one': 1,
                  ':updatedAt': input.transaction.acceptedAt,
                },
              },
            },
            {
              Update: {
                TableName: this.checkoutTableName,
                Key: { PK: checkoutPk(input.checkoutId), SK: 'META' },
                ConditionExpression:
                  '#capabilityHash = :capabilityHash AND #version = :expectedVersion AND attribute_not_exists(#activeTransactionId)',
                UpdateExpression:
                  'SET #status = :status, #version = #version + :one, #activeTransactionId = :transactionId',
                ExpressionAttributeNames: {
                  '#activeTransactionId': 'activeTransactionId',
                  '#capabilityHash': 'capabilityHash',
                  '#status': 'status',
                  '#version': 'version',
                },
                ExpressionAttributeValues: {
                  ':capabilityHash': input.capabilityHash,
                  ':expectedVersion': input.expectedVersion,
                  ':one': 1,
                  ':status': 'PAYMENT_PENDING',
                  ':transactionId': input.transaction.transactionId,
                },
              },
            },
            {
              Put: {
                TableName: this.checkoutTableName,
                Item: payment,
                ConditionExpression: 'attribute_not_exists(PK) AND attribute_not_exists(SK)',
              },
            },
            {
              Put: {
                TableName: this.checkoutTableName,
                Item: reservation,
                ConditionExpression: 'attribute_not_exists(PK) AND attribute_not_exists(SK)',
              },
            },
            {
              Put: {
                TableName: this.checkoutTableName,
                Item: idempotency,
                ConditionExpression: 'attribute_not_exists(PK) AND attribute_not_exists(SK)',
              },
            },
            {
              Put: {
                TableName: this.checkoutTableName,
                Item: this.lockItem(
                  'TRANSACTION',
                  input.transaction.transactionId,
                  input.checkoutId,
                  input.transaction.transactionId,
                ),
                ConditionExpression: 'attribute_not_exists(PK) AND attribute_not_exists(SK)',
              },
            },
          ],
        }),
      );
      return ok({
        kind: 'CREATED',
        checkout: updatedCheckout,
        transaction: input.transaction,
        submission: input.submission,
      });
    } catch (error: unknown) {
      if (!isTransactionCanceled(error)) return err({ code: 'REPOSITORY_UNAVAILABLE' });
      const replay = await this.findIdempotency(input);
      if (!replay.ok) return err(replay.error);
      if (replay.value !== null) return ok(replay.value);
      if (conditionalAt(error, 0)) return err({ code: 'OUT_OF_STOCK' });
      if (conditionalAt(error, 1)) {
        return this.classifyCheckoutWriteFailure(
          error,
          input.checkoutId,
          input.capabilityHash,
          input.expectedVersion,
        );
      }
      return err({ code: 'REPOSITORY_UNAVAILABLE' });
    }
  }

  public async claimDispatch(
    transactionId: string,
    updatedAt: string,
    leaseUntil: string,
  ): Promise<Result<DispatchClaim, CheckoutRepositoryError>> {
    const found = await this.findTransaction(transactionId);
    if (!found.ok || found.value === null) {
      return found.ok ? err({ code: 'CHECKOUT_NOT_FOUND' }) : found;
    }
    if (found.value.dispatchPhase !== 'NOT_SENT' || isTerminalPayment(found.value.paymentStatus)) {
      return ok({ kind: 'NOT_LEADER', transaction: found.value });
    }
    try {
      const response = await this.client.send(
        new UpdateCommand({
          TableName: this.checkoutTableName,
          Key: { PK: checkoutPk(found.value.checkoutId), SK: paymentSk(transactionId) },
          ConditionExpression: '#dispatchPhase = :notSent AND #paymentStatus = :pending',
          UpdateExpression:
            'SET #dispatchPhase = :sending, #updatedAt = :updatedAt, #nextCheckAt = :leaseUntil, #leaseUntil = :leaseUntil, GSI1PK = :gsi1pk, GSI1SK = :gsi1sk',
          ExpressionAttributeNames: {
            '#dispatchPhase': 'dispatchPhase',
            '#leaseUntil': 'leaseUntil',
            '#nextCheckAt': 'nextCheckAt',
            '#paymentStatus': 'paymentStatus',
            '#updatedAt': 'updatedAt',
          },
          ExpressionAttributeValues: {
            ':gsi1pk': 'RECON#DUE',
            ':gsi1sk': leaseUntil + '#' + transactionId,
            ':leaseUntil': leaseUntil,
            ':notSent': 'NOT_SENT',
            ':pending': 'PENDING',
            ':sending': 'SENDING',
            ':updatedAt': updatedAt,
          },
          ReturnValues: 'ALL_NEW',
        }),
      );
      if (!isPaymentItem(response.Attributes)) {
        return err({ code: 'REPOSITORY_UNAVAILABLE' });
      }
      return ok({ kind: 'CLAIMED', transaction: transactionFromItem(response.Attributes) });
    } catch (error: unknown) {
      if (!isConditionalFailure(error)) return err({ code: 'REPOSITORY_UNAVAILABLE' });
      const winner = await this.findTransaction(transactionId);
      return winner.ok && winner.value !== null
        ? ok({ kind: 'NOT_LEADER', transaction: winner.value })
        : err({ code: 'CHECKOUT_NOT_FOUND' });
    }
  }

  public async acknowledgeProvider(
    transactionId: string,
    providerId: string,
    providerStatus: Exclude<ProviderStatus, null>,
    updatedAt: string,
    check: ReconciliationCheck,
  ): Promise<Result<Transaction, CheckoutRepositoryError>> {
    const found = await this.findTransaction(transactionId);
    if (!found.ok || found.value === null) {
      return found.ok ? err({ code: 'CHECKOUT_NOT_FOUND' }) : found;
    }
    const current = found.value;
    if (current.providerId !== undefined && current.providerId !== providerId) {
      return err({ code: 'FINAL_STATE_CONFLICT' });
    }
    if (isTerminalPayment(current.paymentStatus)) {
      return current.providerId === providerId
        ? ok(current)
        : err({ code: 'FINAL_STATE_CONFLICT' });
    }
    const { nextCheckAt: ignoredNext, ...withoutNext } = current;
    void ignoredNext;
    const updated: Transaction = {
      ...withoutNext,
      providerId,
      providerStatus,
      dispatchPhase: 'ACKNOWLEDGED',
      attempts: check.attempts,
      lastCheckedAt: check.lastCheckedAt,
      nextCheckAt: check.nextCheckAt,
      updatedAt,
    };
    try {
      await this.client.send(
        new TransactWriteCommand({
          TransactItems: [
            {
              Update: {
                TableName: this.checkoutTableName,
                Key: { PK: checkoutPk(current.checkoutId), SK: paymentSk(transactionId) },
                ConditionExpression:
                  '#paymentStatus = :pending AND (attribute_not_exists(#providerId) OR #providerId = :providerId)',
                UpdateExpression:
                  'SET #providerId = :providerId, #providerStatus = :providerStatus, #dispatchPhase = :acknowledged, #updatedAt = :updatedAt, #attempts = :attempts, #lastCheckedAt = :lastCheckedAt, #nextCheckAt = :nextCheckAt, GSI1PK = :gsi1pk, GSI1SK = :gsi1sk REMOVE #leaseUntil',
                ExpressionAttributeNames: {
                  '#attempts': 'attempts',
                  '#lastCheckedAt': 'lastCheckedAt',
                  '#dispatchPhase': 'dispatchPhase',
                  '#leaseUntil': 'leaseUntil',
                  '#nextCheckAt': 'nextCheckAt',
                  '#paymentStatus': 'paymentStatus',
                  '#providerId': 'providerId',
                  '#providerStatus': 'providerStatus',
                  '#updatedAt': 'updatedAt',
                },
                ExpressionAttributeValues: {
                  ':attempts': check.attempts,
                  ':lastCheckedAt': check.lastCheckedAt,
                  ':acknowledged': 'ACKNOWLEDGED',
                  ':gsi1pk': 'RECON#DUE',
                  ':gsi1sk': check.nextCheckAt + '#' + transactionId,
                  ':nextCheckAt': check.nextCheckAt,
                  ':pending': 'PENDING',
                  ':providerId': providerId,
                  ':providerStatus': providerStatus,
                  ':updatedAt': updatedAt,
                },
              },
            },
            {
              Put: {
                TableName: this.checkoutTableName,
                Item: this.lockItem('PROVIDER', providerId, current.checkoutId, transactionId),
                ConditionExpression: 'attribute_not_exists(PK) OR #transactionId = :transactionId',
                ExpressionAttributeNames: { '#transactionId': 'transactionId' },
                ExpressionAttributeValues: { ':transactionId': transactionId },
              },
            },
          ],
        }),
      );
      return ok(updated);
    } catch (error: unknown) {
      if (!isTransactionCanceled(error)) return err({ code: 'REPOSITORY_UNAVAILABLE' });
      const latest = await this.findTransaction(transactionId);
      if (latest.ok && latest.value !== null && isTerminalPayment(latest.value.paymentStatus)) {
        return ok(latest.value);
      }
      return err({ code: 'FINAL_STATE_CONFLICT' });
    }
  }

  public async markUnknown(
    transactionId: string,
    updatedAt: string,
    check: ReconciliationCheck,
  ): Promise<Result<Transaction, CheckoutRepositoryError>> {
    const found = await this.findTransaction(transactionId);
    if (!found.ok || found.value === null) {
      return found.ok ? err({ code: 'CHECKOUT_NOT_FOUND' }) : found;
    }
    if (isTerminalPayment(found.value.paymentStatus)) return ok(found.value);
    try {
      const response = await this.client.send(
        new UpdateCommand({
          TableName: this.checkoutTableName,
          Key: { PK: checkoutPk(found.value.checkoutId), SK: paymentSk(transactionId) },
          ConditionExpression: '#paymentStatus = :pending',
          UpdateExpression:
            'SET #dispatchPhase = :unknown, #recoveryCode = :recoveryCode, #updatedAt = :updatedAt, #attempts = :attempts, #lastCheckedAt = :lastCheckedAt, #nextCheckAt = :nextCheckAt, GSI1PK = :gsi1pk, GSI1SK = :gsi1sk REMOVE #leaseUntil',
          ExpressionAttributeNames: {
            '#dispatchPhase': 'dispatchPhase',
            '#attempts': 'attempts',
            '#lastCheckedAt': 'lastCheckedAt',
            '#leaseUntil': 'leaseUntil',
            '#nextCheckAt': 'nextCheckAt',
            '#paymentStatus': 'paymentStatus',
            '#recoveryCode': 'recoveryCode',
            '#updatedAt': 'updatedAt',
          },
          ExpressionAttributeValues: {
            ':gsi1pk': 'RECON#DUE',
            ':attempts': check.attempts,
            ':lastCheckedAt': check.lastCheckedAt,
            ':gsi1sk': check.nextCheckAt + '#' + transactionId,
            ':nextCheckAt': check.nextCheckAt,
            ':pending': 'PENDING',
            ':recoveryCode': 'PROVIDER_OUTCOME_UNKNOWN',
            ':unknown': 'UNKNOWN',
            ':updatedAt': updatedAt,
          },
          ReturnValues: 'ALL_NEW',
        }),
      );
      return isPaymentItem(response.Attributes)
        ? ok(transactionFromItem(response.Attributes))
        : err({ code: 'REPOSITORY_UNAVAILABLE' });
    } catch (error: unknown) {
      if (!isConditionalFailure(error)) return err({ code: 'REPOSITORY_UNAVAILABLE' });
      const latest = await this.findTransaction(transactionId);
      return latest.ok && latest.value !== null && isTerminalPayment(latest.value.paymentStatus)
        ? ok(latest.value)
        : err({ code: 'FINAL_STATE_CONFLICT' });
    }
  }

  public async finalize(
    transactionId: string,
    status: Exclude<PaymentStatus, 'PENDING'>,
    providerStatus: ProviderStatus,
    recoveryCode: Transaction['recoveryCode'],
    updatedAt: string,
  ): Promise<Result<Transaction, CheckoutRepositoryError>> {
    const stored = await this.findStoredPaymentByLock('TRANSACTION', transactionId);
    if (!stored.ok || stored.value === null) {
      return stored.ok ? err({ code: 'CHECKOUT_NOT_FOUND' }) : stored;
    }
    const current = transactionFromItem(stored.value);
    if (isTerminalPayment(current.paymentStatus)) {
      return current.paymentStatus === status
        ? ok(current)
        : this.recordFinalConflict(current, updatedAt);
    }
    if (
      recoveryCode === 'PROVIDER_NOT_SENT' &&
      (status !== 'ERROR' ||
        providerStatus !== null ||
        current.providerId !== undefined ||
        (current.dispatchPhase !== 'SENDING' && current.dispatchPhase !== 'NOT_SENT_FAILED'))
    ) {
      return err({ code: 'FINAL_STATE_CONFLICT' });
    }
    if (
      recoveryCode === undefined &&
      (providerStatus === null ||
        providerStatus !== status ||
        current.providerStatus !== providerStatus ||
        current.providerId === undefined ||
        current.dispatchPhase !== 'ACKNOWLEDGED')
    ) {
      return err({ code: 'FINAL_STATE_CONFLICT' });
    }

    const [checkout, reservation] = await Promise.all([
      this.findCheckout(current.checkoutId),
      this.getReservation(current.checkoutId, transactionId),
    ]);
    if (!checkout.ok || checkout.value === null || !reservation.ok || reservation.value === null) {
      return status === 'APPROVED'
        ? this.recordApprovedInventoryConflict(
            current,
            stored.value.idempotencyKeyHash,
            providerStatus,
            updatedAt,
          )
        : err({ code: 'REPOSITORY_UNAVAILABLE' });
    }
    if (
      reservation.value.status !== 'ACTIVE' ||
      reservation.value.productId !== checkout.value.productId
    ) {
      return status === 'APPROVED'
        ? this.recordApprovedInventoryConflict(
            current,
            stored.value.idempotencyKeyHash,
            providerStatus,
            updatedAt,
          )
        : err({ code: 'FINAL_STATE_CONFLICT' });
    }
    return status === 'APPROVED'
      ? this.finalizeApproved(
          current,
          stored.value.idempotencyKeyHash,
          checkout.value,
          providerStatus,
          updatedAt,
        )
      : this.finalizeFailure(
          current,
          stored.value.idempotencyKeyHash,
          checkout.value,
          status,
          providerStatus,
          recoveryCode,
          updatedAt,
        );
  }

  public async findTransaction(
    transactionId: string,
  ): Promise<Result<Transaction | null, CheckoutRepositoryError>> {
    const found = await this.findStoredPaymentByLock('TRANSACTION', transactionId);
    return found.ok ? ok(found.value === null ? null : transactionFromItem(found.value)) : found;
  }

  public async findTransactionByProviderId(
    providerId: string,
  ): Promise<Result<Transaction | null, CheckoutRepositoryError>> {
    const found = await this.findStoredPaymentByLock('PROVIDER', providerId);
    return found.ok ? ok(found.value === null ? null : transactionFromItem(found.value)) : found;
  }

  public async recordWebhook(
    eventHash: string,
  ): Promise<Result<'NEW' | 'DUPLICATE', CheckoutRepositoryError>> {
    try {
      await this.client.send(
        new TransactWriteCommand({
          TransactItems: [
            {
              Put: {
                TableName: this.checkoutTableName,
                Item: {
                  PK: 'WEBHOOK#' + eventHash,
                  SK: 'DEDUPE',
                  itemType: 'WEBHOOK_DEDUPE',
                  schemaVersion: 1,
                },
                ConditionExpression: 'attribute_not_exists(PK) AND attribute_not_exists(SK)',
              },
            },
          ],
        }),
      );
      return ok('NEW');
    } catch (error: unknown) {
      return isTransactionCanceled(error) && conditionalAt(error, 0)
        ? ok('DUPLICATE')
        : err({ code: 'REPOSITORY_UNAVAILABLE' });
    }
  }

  public async findOldestPendingAcceptedAt(): Promise<
    Result<string | null, CheckoutRepositoryError>
  > {
    try {
      const response = await this.client.send(
        new QueryCommand({
          TableName: this.checkoutTableName,
          IndexName: 'GSI2-PendingAge',
          KeyConditionExpression: 'GSI2PK = :pending',
          ExpressionAttributeValues: { ':pending': 'PAYMENT#PENDING' },
          ProjectionExpression: 'acceptedAt, paymentStatus',
          ScanIndexForward: true,
          Limit: 1,
          ConsistentRead: false,
        }),
      );
      const items = response.Items ?? [];
      if (items.length === 0) return ok(null);
      const oldest = items[0];
      return isOldestPendingProjection(oldest) && Number.isFinite(Date.parse(oldest.acceptedAt))
        ? ok(oldest.acceptedAt)
        : err({ code: 'REPOSITORY_UNAVAILABLE' });
    } catch {
      return err({ code: 'REPOSITORY_UNAVAILABLE' });
    }
  }

  public async claimDue(
    now: string,
    leaseUntil: string,
    limit: number,
  ): Promise<Result<readonly Transaction[], CheckoutRepositoryError>> {
    try {
      const response = await this.client.send(
        new QueryCommand({
          TableName: this.checkoutTableName,
          IndexName: 'GSI1-Reconcile',
          KeyConditionExpression: 'GSI1PK = :due AND GSI1SK <= :upper',
          ExpressionAttributeValues: {
            ':due': 'RECON#DUE',
            ':upper': now + '#' + '\uffff',
          },
          Limit: Math.min(Math.max(limit, 1), 10),
          ConsistentRead: false,
        }),
      );
      const claimed: Transaction[] = [];
      for (const projected of response.Items ?? []) {
        if (!isReconcileCandidate(projected)) {
          return err({ code: 'REPOSITORY_UNAVAILABLE' });
        }
        const base = await this.client.send(
          new GetCommand({
            TableName: this.checkoutTableName,
            Key: { PK: projected.PK, SK: projected.SK },
            ConsistentRead: true,
          }),
        );
        if (base.Item === undefined) continue;
        if (
          !isPaymentItem(base.Item) ||
          base.Item.checkoutId !== projected.checkoutId ||
          base.Item.transactionId !== projected.transactionId
        ) {
          return err({ code: 'REPOSITORY_UNAVAILABLE' });
        }
        const candidate = base.Item;
        if (
          candidate.paymentStatus !== 'PENDING' ||
          candidate.nextCheckAt === undefined ||
          candidate.nextCheckAt > now
        ) {
          continue;
        }
        const recoverNotSent = candidate.dispatchPhase === 'NOT_SENT';
        try {
          const updated = await this.client.send(
            new UpdateCommand({
              TableName: this.checkoutTableName,
              Key: {
                PK: checkoutPk(candidate.checkoutId),
                SK: paymentSk(candidate.transactionId),
              },
              ConditionExpression:
                '#paymentStatus = :pending AND #dispatchPhase = :expectedDispatchPhase AND #nextCheckAt <= :now AND (attribute_not_exists(#leaseUntil) OR #leaseUntil < :now)',
              UpdateExpression:
                'SET #leaseUntil = :leaseUntil, #nextCheckAt = :leaseUntil, GSI1SK = :gsi1sk' +
                (recoverNotSent ? ', #dispatchPhase = :notSentFailed' : ''),
              ExpressionAttributeNames: {
                '#dispatchPhase': 'dispatchPhase',
                '#leaseUntil': 'leaseUntil',
                '#nextCheckAt': 'nextCheckAt',
                '#paymentStatus': 'paymentStatus',
              },
              ExpressionAttributeValues: {
                ':expectedDispatchPhase': candidate.dispatchPhase,
                ':gsi1sk': leaseUntil + '#' + candidate.transactionId,
                ':leaseUntil': leaseUntil,
                ':now': now,
                ':pending': 'PENDING',
                ...(recoverNotSent ? { ':notSentFailed': 'NOT_SENT_FAILED' } : {}),
              },
              ReturnValues: 'ALL_NEW',
            }),
          );
          if (!isPaymentItem(updated.Attributes)) {
            return err({ code: 'REPOSITORY_UNAVAILABLE' });
          }
          claimed.push(transactionFromItem(updated.Attributes));
        } catch (error: unknown) {
          if (!isConditionalFailure(error)) {
            return err({ code: 'REPOSITORY_UNAVAILABLE' });
          }
        }
      }
      return ok(claimed);
    } catch {
      return err({ code: 'REPOSITORY_UNAVAILABLE' });
    }
  }

  public async findDelivery(
    deliveryId: string,
  ): Promise<Result<Delivery | null, CheckoutRepositoryError>> {
    try {
      const lock = await this.client.send(
        new GetCommand({
          TableName: this.checkoutTableName,
          Key: { PK: this.lockPk('DELIVERY', deliveryId), SK: 'LOCK' },
          ConsistentRead: true,
        }),
      );
      if (lock.Item === undefined) return ok(null);
      if (!isLockItem(lock.Item, 'DELIVERY')) {
        return err({ code: 'REPOSITORY_UNAVAILABLE' });
      }
      const response = await this.client.send(
        new GetCommand({
          TableName: this.checkoutTableName,
          Key: { PK: checkoutPk(lock.Item.checkoutId), SK: deliverySk(deliveryId) },
          ConsistentRead: true,
        }),
      );
      if (response.Item === undefined) return ok(null);
      return isDeliveryItem(response.Item)
        ? ok(deliveryFromItem(response.Item))
        : err({ code: 'REPOSITORY_UNAVAILABLE' });
    } catch {
      return err({ code: 'REPOSITORY_UNAVAILABLE' });
    }
  }

  private async finalizeApproved(
    current: Transaction,
    idempotencyKeyHash: string,
    checkout: Checkout,
    providerStatus: ProviderStatus,
    updatedAt: string,
  ): Promise<Result<Transaction, CheckoutRepositoryError>> {
    if (checkout.deliveryDetails === undefined) {
      return this.recordApprovedInventoryConflict(
        current,
        idempotencyKeyHash,
        providerStatus,
        updatedAt,
      );
    }
    const deliveryId = 'delivery_' + current.transactionId;
    const {
      checkoutId: ignoredCheckout,
      version: ignoredVersion,
      ...destination
    } = checkout.deliveryDetails;
    void ignoredCheckout;
    void ignoredVersion;
    const delivery: Delivery = {
      deliveryId,
      checkoutId: checkout.checkoutId,
      transactionId: current.transactionId,
      status: 'CREATED',
      destination,
      createdAt: updatedAt,
      updatedAt,
    };
    const {
      nextCheckAt: ignoredNext,
      recoveryCode: ignoredRecovery,
      ...withoutTransient
    } = current;
    void ignoredNext;
    void ignoredRecovery;
    const finalized: Transaction = {
      ...withoutTransient,
      paymentStatus: 'APPROVED',
      providerStatus,
      dispatchPhase: 'ACKNOWLEDGED',
      reservationStatus: 'CONSUMED',
      integrityStatus: 'OK',
      deliveryId,
      effectsApplied: true,
      updatedAt,
    };
    try {
      await this.client.send(
        new TransactWriteCommand({
          TransactItems: [
            this.finalPaymentUpdate(current, finalized),
            {
              Update: {
                TableName: this.checkoutTableName,
                Key: {
                  PK: checkoutPk(checkout.checkoutId),
                  SK: reservationSk(current.transactionId),
                },
                ConditionExpression: '#status = :active AND #transactionId = :transactionId',
                UpdateExpression: 'SET #status = :consumed, #updatedAt = :updatedAt',
                ExpressionAttributeNames: {
                  '#status': 'status',
                  '#transactionId': 'transactionId',
                  '#updatedAt': 'updatedAt',
                },
                ExpressionAttributeValues: {
                  ':active': 'ACTIVE',
                  ':consumed': 'CONSUMED',
                  ':transactionId': current.transactionId,
                  ':updatedAt': updatedAt,
                },
              },
            },
            {
              Update: {
                TableName: this.catalogTableName,
                Key: { PK: 'PRODUCT#' + checkout.productId, SK: 'META' },
                ConditionExpression: '#reserved >= :one AND #onHand >= :one',
                UpdateExpression:
                  'SET #onHand = #onHand - :one, #reserved = #reserved - :one, #version = #version + :one, #updatedAt = :updatedAt',
                ExpressionAttributeNames: {
                  '#onHand': 'onHand',
                  '#reserved': 'reserved',
                  '#updatedAt': 'updatedAt',
                  '#version': 'version',
                },
                ExpressionAttributeValues: {
                  ':one': 1,
                  ':updatedAt': updatedAt,
                },
              },
            },
            {
              Put: {
                TableName: this.checkoutTableName,
                Item: {
                  ...delivery,
                  PK: checkoutPk(checkout.checkoutId),
                  SK: deliverySk(deliveryId),
                  itemType: 'DELIVERY',
                  schemaVersion: 1,
                } satisfies StoredDelivery,
                ConditionExpression: 'attribute_not_exists(PK) OR #transactionId = :transactionId',
                ExpressionAttributeNames: { '#transactionId': 'transactionId' },
                ExpressionAttributeValues: { ':transactionId': current.transactionId },
              },
            },
            {
              Put: {
                TableName: this.checkoutTableName,
                Item: this.lockItem(
                  'DELIVERY',
                  deliveryId,
                  checkout.checkoutId,
                  current.transactionId,
                ),
                ConditionExpression: 'attribute_not_exists(PK) OR #transactionId = :transactionId',
                ExpressionAttributeNames: { '#transactionId': 'transactionId' },
                ExpressionAttributeValues: { ':transactionId': current.transactionId },
              },
            },
            this.checkoutFinalUpdate(checkout.checkoutId, current.transactionId, 'PAID'),
            this.idempotencyFinalUpdate(
              current.checkoutId,
              current.transactionId,
              idempotencyKeyHash,
              updatedAt,
            ),
          ],
        }),
      );
      return ok(finalized);
    } catch (error: unknown) {
      if (!isTransactionCanceled(error)) return err({ code: 'REPOSITORY_UNAVAILABLE' });
      const latest = await this.findTransaction(current.transactionId);
      if (latest.ok && latest.value !== null && isTerminalPayment(latest.value.paymentStatus)) {
        return latest.value.paymentStatus === 'APPROVED'
          ? ok(latest.value)
          : this.recordFinalConflict(latest.value, updatedAt);
      }
      if (conditionalAt(error, 0)) return err({ code: 'FINAL_STATE_CONFLICT' });
      if (conditionalAt(error, 1) || conditionalAt(error, 2)) {
        return this.recordApprovedInventoryConflict(
          current,
          idempotencyKeyHash,
          providerStatus,
          updatedAt,
        );
      }
      return err({ code: 'REPOSITORY_UNAVAILABLE' });
    }
  }

  private async finalizeFailure(
    current: Transaction,
    idempotencyKeyHash: string,
    checkout: Checkout,
    status: Exclude<PaymentStatus, 'PENDING' | 'APPROVED'>,
    providerStatus: ProviderStatus,
    recoveryCode: Transaction['recoveryCode'],
    updatedAt: string,
  ): Promise<Result<Transaction, CheckoutRepositoryError>> {
    const {
      nextCheckAt: ignoredNext,
      recoveryCode: ignoredRecovery,
      deliveryId: ignoredDelivery,
      ...withoutTransient
    } = current;
    void ignoredNext;
    void ignoredRecovery;
    void ignoredDelivery;
    const finalized: Transaction = {
      ...withoutTransient,
      paymentStatus: status,
      providerStatus,
      dispatchPhase: recoveryCode === 'PROVIDER_NOT_SENT' ? 'NOT_SENT_FAILED' : 'ACKNOWLEDGED',
      reservationStatus: 'RELEASED',
      integrityStatus: 'OK',
      ...(recoveryCode === undefined ? {} : { recoveryCode }),
      effectsApplied: true,
      updatedAt,
    };
    try {
      await this.client.send(
        new TransactWriteCommand({
          TransactItems: [
            this.finalPaymentUpdate(current, finalized),
            {
              Update: {
                TableName: this.checkoutTableName,
                Key: {
                  PK: checkoutPk(checkout.checkoutId),
                  SK: reservationSk(current.transactionId),
                },
                ConditionExpression: '#status = :active AND #transactionId = :transactionId',
                UpdateExpression: 'SET #status = :released, #updatedAt = :updatedAt',
                ExpressionAttributeNames: {
                  '#status': 'status',
                  '#transactionId': 'transactionId',
                  '#updatedAt': 'updatedAt',
                },
                ExpressionAttributeValues: {
                  ':active': 'ACTIVE',
                  ':released': 'RELEASED',
                  ':transactionId': current.transactionId,
                  ':updatedAt': updatedAt,
                },
              },
            },
            {
              Update: {
                TableName: this.catalogTableName,
                Key: { PK: 'PRODUCT#' + checkout.productId, SK: 'META' },
                ConditionExpression: '#reserved >= :one',
                UpdateExpression:
                  'SET #reserved = #reserved - :one, #available = #available + :one, #version = #version + :one, #updatedAt = :updatedAt',
                ExpressionAttributeNames: {
                  '#available': 'available',
                  '#reserved': 'reserved',
                  '#updatedAt': 'updatedAt',
                  '#version': 'version',
                },
                ExpressionAttributeValues: {
                  ':one': 1,
                  ':updatedAt': updatedAt,
                },
              },
            },
            this.checkoutFinalUpdate(
              checkout.checkoutId,
              current.transactionId,
              checkoutStatusForPayment(status),
            ),
            this.idempotencyFinalUpdate(
              current.checkoutId,
              current.transactionId,
              idempotencyKeyHash,
              updatedAt,
            ),
          ],
        }),
      );
      return ok(finalized);
    } catch (error: unknown) {
      if (!isTransactionCanceled(error)) return err({ code: 'REPOSITORY_UNAVAILABLE' });
      const latest = await this.findTransaction(current.transactionId);
      if (latest.ok && latest.value !== null && isTerminalPayment(latest.value.paymentStatus)) {
        return latest.value.paymentStatus === status
          ? ok(latest.value)
          : this.recordFinalConflict(latest.value, updatedAt);
      }
      if (conditionalAt(error, 0)) return err({ code: 'FINAL_STATE_CONFLICT' });
      return err({ code: 'REPOSITORY_UNAVAILABLE' });
    }
  }

  private finalPaymentUpdate(current: Transaction, finalized: Transaction): TransactItem {
    const setRecovery =
      finalized.recoveryCode === undefined ? '' : ', #recoveryCode = :recoveryCode';
    const removeRecovery = finalized.recoveryCode === undefined ? ', #recoveryCode' : '';
    const requireProviderProof = finalized.recoveryCode === undefined;
    const requireDispatchProof =
      requireProviderProof || finalized.recoveryCode === 'PROVIDER_NOT_SENT';

    return {
      Update: {
        TableName: this.checkoutTableName,
        Key: { PK: checkoutPk(current.checkoutId), SK: paymentSk(current.transactionId) },
        ConditionExpression:
          '#paymentStatus = :pending AND #reservationStatus = :active AND #effectsApplied = :false' +
          (requireDispatchProof ? ' AND #dispatchPhase = :expectedDispatchPhase' : '') +
          (requireProviderProof
            ? ' AND #providerId = :expectedProviderId AND #providerStatus = :expectedProviderStatus'
            : ''),
        UpdateExpression:
          'SET #paymentStatus = :paymentStatus, #providerStatus = :providerStatus, #dispatchPhase = :dispatchPhase, #reservationStatus = :reservationStatus, #integrityStatus = :integrityStatus, #effectsApplied = :true, #updatedAt = :updatedAt' +
          (finalized.deliveryId === undefined ? '' : ', #deliveryId = :deliveryId') +
          setRecovery +
          ' REMOVE #nextCheckAt, #leaseUntil, GSI1PK, GSI1SK, GSI2PK, GSI2SK' +
          removeRecovery,
        ExpressionAttributeNames: {
          ...(requireProviderProof ? { '#providerId': 'providerId' } : {}),
          ...(finalized.deliveryId === undefined ? {} : { '#deliveryId': 'deliveryId' }),
          '#dispatchPhase': 'dispatchPhase',
          '#effectsApplied': 'effectsApplied',
          '#integrityStatus': 'integrityStatus',
          '#leaseUntil': 'leaseUntil',
          '#nextCheckAt': 'nextCheckAt',
          '#paymentStatus': 'paymentStatus',
          '#providerStatus': 'providerStatus',
          '#recoveryCode': 'recoveryCode',
          '#reservationStatus': 'reservationStatus',
          '#updatedAt': 'updatedAt',
        },
        ExpressionAttributeValues: {
          ':active': 'ACTIVE',
          ':dispatchPhase': finalized.dispatchPhase,
          ':false': false,
          ':integrityStatus': finalized.integrityStatus,
          ':paymentStatus': finalized.paymentStatus,
          ':pending': 'PENDING',
          ':providerStatus': finalized.providerStatus,
          ':reservationStatus': finalized.reservationStatus,
          ':true': true,
          ':updatedAt': finalized.updatedAt,
          ...(finalized.deliveryId === undefined ? {} : { ':deliveryId': finalized.deliveryId }),
          ...(finalized.recoveryCode === undefined
            ? {}
            : { ':recoveryCode': finalized.recoveryCode }),
          ...(requireDispatchProof ? { ':expectedDispatchPhase': current.dispatchPhase } : {}),
          ...(requireProviderProof
            ? {
                ':expectedProviderId': current.providerId,
                ':expectedProviderStatus': current.providerStatus,
              }
            : {}),
        },
      },
    };
  }

  private checkoutFinalUpdate(
    checkoutId: string,
    transactionId: string,
    status: Checkout['status'],
  ): TransactItem {
    return {
      Update: {
        TableName: this.checkoutTableName,
        Key: { PK: checkoutPk(checkoutId), SK: 'META' },
        ConditionExpression: '#activeTransactionId = :transactionId',
        UpdateExpression: 'SET #status = :status',
        ExpressionAttributeNames: {
          '#activeTransactionId': 'activeTransactionId',
          '#status': 'status',
        },
        ExpressionAttributeValues: {
          ':status': status,
          ':transactionId': transactionId,
        },
      },
    };
  }

  private idempotencyFinalUpdate(
    checkoutId: string,
    transactionId: string,
    keyHash: string,
    updatedAt: string,
  ): TransactItem {
    return {
      Update: {
        TableName: this.checkoutTableName,
        Key: { PK: checkoutPk(checkoutId), SK: idempotencySk(keyHash) },
        ConditionExpression: '#transactionId = :transactionId',
        UpdateExpression: 'SET #status = :final, #updatedAt = :updatedAt',
        ExpressionAttributeNames: {
          '#status': 'status',
          '#transactionId': 'transactionId',
          '#updatedAt': 'updatedAt',
        },
        ExpressionAttributeValues: {
          ':final': 'FINAL',
          ':transactionId': transactionId,
          ':updatedAt': updatedAt,
        },
      },
    };
  }

  private async recordApprovedInventoryConflict(
    current: Transaction,
    idempotencyKeyHash: string,
    providerStatus: ProviderStatus,
    updatedAt: string,
  ): Promise<Result<Transaction, CheckoutRepositoryError>> {
    const {
      nextCheckAt: ignoredNext,
      recoveryCode: ignoredRecovery,
      ...withoutTransient
    } = current;
    void ignoredNext;
    void ignoredRecovery;
    const conflicted: Transaction = {
      ...withoutTransient,
      paymentStatus: 'APPROVED',
      providerStatus,
      dispatchPhase: 'ACKNOWLEDGED',
      integrityStatus: 'APPROVED_INVENTORY_CONFLICT',
      recoveryCode: 'STATE_TRANSITION_CONFLICT',
      effectsApplied: false,
      updatedAt,
    };
    try {
      await this.client.send(
        new TransactWriteCommand({
          TransactItems: [
            {
              Update: {
                TableName: this.checkoutTableName,
                Key: {
                  PK: checkoutPk(current.checkoutId),
                  SK: paymentSk(current.transactionId),
                },
                ConditionExpression: '#paymentStatus = :pending',
                UpdateExpression:
                  'SET #paymentStatus = :approved, #providerStatus = :providerStatus, #dispatchPhase = :acknowledged, #integrityStatus = :integrityStatus, #recoveryCode = :recoveryCode, #updatedAt = :updatedAt REMOVE #nextCheckAt, #leaseUntil, GSI1PK, GSI1SK, GSI2PK, GSI2SK',
                ExpressionAttributeNames: {
                  '#dispatchPhase': 'dispatchPhase',
                  '#integrityStatus': 'integrityStatus',
                  '#leaseUntil': 'leaseUntil',
                  '#nextCheckAt': 'nextCheckAt',
                  '#paymentStatus': 'paymentStatus',
                  '#providerStatus': 'providerStatus',
                  '#recoveryCode': 'recoveryCode',
                  '#updatedAt': 'updatedAt',
                },
                ExpressionAttributeValues: {
                  ':acknowledged': 'ACKNOWLEDGED',
                  ':approved': 'APPROVED',
                  ':integrityStatus': 'APPROVED_INVENTORY_CONFLICT',
                  ':pending': 'PENDING',
                  ':providerStatus': providerStatus,
                  ':recoveryCode': 'STATE_TRANSITION_CONFLICT',
                  ':updatedAt': updatedAt,
                },
              },
            },
            this.checkoutFinalUpdate(current.checkoutId, current.transactionId, 'PAID'),
            this.idempotencyFinalUpdate(
              current.checkoutId,
              current.transactionId,
              idempotencyKeyHash,
              updatedAt,
            ),
          ],
        }),
      );
      return ok(conflicted);
    } catch {
      const latest = await this.findTransaction(current.transactionId);
      return latest.ok && latest.value !== null
        ? ok(latest.value)
        : err({ code: 'APPROVED_INVENTORY_CONFLICT' });
    }
  }

  private async recordFinalConflict(
    current: Transaction,
    updatedAt: string,
  ): Promise<Result<Transaction, CheckoutRepositoryError>> {
    try {
      const response = await this.client.send(
        new UpdateCommand({
          TableName: this.checkoutTableName,
          Key: { PK: checkoutPk(current.checkoutId), SK: paymentSk(current.transactionId) },
          ConditionExpression: '#paymentStatus = :currentStatus',
          UpdateExpression:
            'SET #integrityStatus = :conflict, #recoveryCode = :recoveryCode, #updatedAt = :updatedAt',
          ExpressionAttributeNames: {
            '#integrityStatus': 'integrityStatus',
            '#paymentStatus': 'paymentStatus',
            '#recoveryCode': 'recoveryCode',
            '#updatedAt': 'updatedAt',
          },
          ExpressionAttributeValues: {
            ':conflict': 'FINAL_STATE_CONFLICT',
            ':currentStatus': current.paymentStatus,
            ':recoveryCode': 'STATE_TRANSITION_CONFLICT',
            ':updatedAt': updatedAt,
          },
          ReturnValues: 'ALL_NEW',
        }),
      );
      return isPaymentItem(response.Attributes)
        ? ok(transactionFromItem(response.Attributes))
        : err({ code: 'FINAL_STATE_CONFLICT' });
    } catch {
      return err({ code: 'FINAL_STATE_CONFLICT' });
    }
  }

  private async classifyCheckoutWriteFailure(
    transactionError: unknown,
    checkoutId: string,
    capabilityHash: string,
    expectedVersion: number,
  ): Promise<Result<never, CheckoutRepositoryError>> {
    if (!isTransactionCanceled(transactionError)) {
      return err({ code: 'REPOSITORY_UNAVAILABLE' });
    }
    const latest = await this.findCheckout(checkoutId);
    if (!latest.ok) return err({ code: 'REPOSITORY_UNAVAILABLE' });
    if (latest.value === null || latest.value.capabilityHash !== capabilityHash) {
      return err({ code: 'CHECKOUT_NOT_FOUND' });
    }
    if (latest.value.version !== expectedVersion) {
      return err({ code: 'VERSION_MISMATCH' });
    }
    return latest.value.activeTransactionId === undefined
      ? err({ code: 'REPOSITORY_UNAVAILABLE' })
      : err({ code: 'PAYMENT_ALREADY_IN_PROGRESS' });
  }

  private async findStoredPaymentByLock(
    kind: 'TRANSACTION' | 'PROVIDER',
    value: string,
  ): Promise<Result<StoredPayment | null, CheckoutRepositoryError>> {
    try {
      const response = await this.client.send(
        new GetCommand({
          TableName: this.checkoutTableName,
          Key: { PK: this.lockPk(kind, value), SK: 'LOCK' },
          ConsistentRead: true,
        }),
      );
      if (response.Item === undefined) return ok(null);
      if (!isLockItem(response.Item, kind)) {
        return err({ code: 'REPOSITORY_UNAVAILABLE' });
      }
      return this.getStoredPayment(response.Item.checkoutId, response.Item.transactionId);
    } catch {
      return err({ code: 'REPOSITORY_UNAVAILABLE' });
    }
  }

  private async getStoredPayment(
    checkoutId: string,
    transactionId: string,
  ): Promise<Result<StoredPayment | null, CheckoutRepositoryError>> {
    try {
      const response = await this.client.send(
        new GetCommand({
          TableName: this.checkoutTableName,
          Key: { PK: checkoutPk(checkoutId), SK: paymentSk(transactionId) },
          ConsistentRead: true,
        }),
      );
      if (response.Item === undefined) return ok(null);
      return isPaymentItem(response.Item)
        ? ok(response.Item)
        : err({ code: 'REPOSITORY_UNAVAILABLE' });
    } catch {
      return err({ code: 'REPOSITORY_UNAVAILABLE' });
    }
  }

  private async getReservation(
    checkoutId: string,
    transactionId: string,
  ): Promise<Result<StoredReservation | null, CheckoutRepositoryError>> {
    try {
      const response = await this.client.send(
        new GetCommand({
          TableName: this.checkoutTableName,
          Key: { PK: checkoutPk(checkoutId), SK: reservationSk(transactionId) },
          ConsistentRead: true,
        }),
      );
      if (response.Item === undefined) return ok(null);
      return isReservationItem(response.Item)
        ? ok(response.Item)
        : err({ code: 'REPOSITORY_UNAVAILABLE' });
    } catch {
      return err({ code: 'REPOSITORY_UNAVAILABLE' });
    }
  }

  private lockItem(
    kind: LookupKind,
    value: string,
    checkoutId: string,
    transactionId: string,
  ): StoredLock {
    return {
      PK: this.lockPk(kind, value),
      SK: 'LOCK',
      itemType: 'UNIQUE_LOCK',
      kind,
      checkoutId,
      transactionId,
      schemaVersion: 1,
    };
  }

  private lockPk(kind: LookupKind, value: string): string {
    const digest = this.hmacLookup(kind + '|' + value);
    if (!/^[A-Za-z0-9_-]{32,128}$/.test(digest)) {
      throw new Error('Lookup HMAC must be base64url and at least 256 bits');
    }
    return 'UNIQUE#' + kind + '#' + digest;
  }
}
